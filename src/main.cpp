#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <filesystem>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <cstring>
#include <cstdlib>

#include "duktape.h"
#include "aes.h"
#include "miniz.h"
#include "resource_format.h"

namespace fs = std::filesystem;

static std::string readFile(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f)
        throw std::runtime_error("Cannot open file: " + path.string());
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::vector<fs::path> g_dirStack;
static std::vector<std::string> g_resourceDirStack;

static std::unordered_map<std::string, std::string> g_resourceFiles;
static bool g_resourceMode = false;

static uint32_t readU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

static bool loadResource(const std::string& path, const std::string& password) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::cerr << "[CryoJS] Cannot open resource: " << path << '\n';
        return false;
    }

    std::vector<uint8_t> raw((std::istreambuf_iterator<char>(f)),
                              std::istreambuf_iterator<char>());

    if (raw.size() < 4 + 12 + 4 + SALT_SIZE + IV_SIZE + 4) {
        std::cerr << "[CryoJS] Resource file too small\n";
        return false;
    }

    bool v2 = false;
    const uint8_t* magic = nullptr;
    if (memcmp(raw.data(), MAGIC_V2, 4) == 0) {
        magic = MAGIC_V2;
        v2 = true;
    } else if (memcmp(raw.data(), MAGIC_V1, 4) == 0) {
        magic = MAGIC_V1;
    } else {
        std::cerr << "[CryoJS] Invalid resource file\n";
        return false;
    }

    for (size_t i = 4; i < raw.size(); i++)
        raw[i] ^= magic[i % 4];

    uint8_t flags = 0;
    if (v2) {
        uint8_t version = raw[4];
        flags = raw[5];
        if (version != FORMAT_VERSION) {
            std::cerr << "[CryoJS] Unsupported resource format version: "
                      << static_cast<int>(version) << '\n';
            return false;
        }
    }

    // v1: 12 random padding bytes; v2: version + flags + 10 padding bytes
    size_t pos = 4 + 12;

    uint32_t fileCountObf = readU32LE(raw.data() + pos); pos += 4;
    uint32_t fileCount    = fileCountObf ^ XOR_MASK;

    const uint8_t* salt = raw.data() + pos; pos += SALT_SIZE;
    const uint8_t* iv   = raw.data() + pos; pos += IV_SIZE;

    uint32_t encSize = readU32LE(raw.data() + pos); pos += 4;

    if (pos + encSize > raw.size()) {
        std::cerr << "[CryoJS] Corrupted resource file\n";
        return false;
    }

    std::vector<uint8_t> encrypted(raw.data() + pos, raw.data() + pos + encSize);

    uint8_t key[KEY_SIZE];
    deriveKey(password, salt, key);

    struct AES_ctx aesCtx;
    AES_init_ctx_iv(&aesCtx, key, iv);
    AES_CBC_decrypt_buffer(&aesCtx, encrypted.data(), encrypted.size());

    if (encrypted.empty()) {
        std::cerr << "[CryoJS] Decryption produced empty result\n";
        return false;
    }

    uint8_t padByte = encrypted.back();
    if (padByte == 0 || padByte > 16) {
        std::cerr << "[CryoJS] Wrong password or corrupted data\n";
        return false;
    }

    bool paddingValid = true;
    for (size_t i = encrypted.size() - padByte; i < encrypted.size(); i++) {
        if (encrypted[i] != padByte) {
            paddingValid = false;
            break;
        }
    }
    if (!paddingValid) {
        std::cerr << "[CryoJS] Wrong password or corrupted data\n";
        return false;
    }

    size_t paddedSize = encrypted.size() - padByte;

    const uint8_t* plain = nullptr;
    size_t plainSize = 0;
    std::vector<uint8_t> plainBuf;

    if (flags & FLAG_COMPRESSED) {
        if (paddedSize < 4) {
            std::cerr << "[CryoJS] Wrong password or corrupted data\n";
            return false;
        }

        uint32_t origSize = readU32LE(encrypted.data());
        constexpr uint32_t MAX_ORIG_SIZE = 512u * 1024 * 1024;
        if (origSize == 0 || origSize > MAX_ORIG_SIZE) {
            std::cerr << "[CryoJS] Wrong password or corrupted data\n";
            return false;
        }

        plainBuf.resize(origSize);
        mz_ulong destLen = origSize;
        mz_ulong srcLen  = paddedSize - 4;
        if (mz_uncompress(plainBuf.data(), &destLen,
                          encrypted.data() + 4, srcLen) != MZ_OK ||
            destLen != origSize)
        {
            std::cerr << "[CryoJS] Failed to decompress resource payload\n";
            return false;
        }
        plain = plainBuf.data();
        plainSize = origSize;
    } else {
        plain = encrypted.data();
        plainSize = paddedSize;
    }

    if (plainSize < 8) {
        std::cerr << "[CryoJS] Wrong password or corrupted data\n";
        return false;
    }

    uint32_t checksum = 0;
    for (size_t i = 0; i < plainSize - 4; i++)
        checksum = checksum * 31 + plain[i];
    uint32_t storedChecksum = readU32LE(plain + plainSize - 4);
    if (checksum != storedChecksum) {
        std::cerr << "[CryoJS] Wrong password (checksum mismatch)\n";
        return false;
    }

    size_t ppos = 0;
    uint32_t fcount = readU32LE(plain + ppos); ppos += 4;
    if (fcount != fileCount) {
        std::cerr << "[CryoJS] Resource integrity error\n";
        return false;
    }

    for (uint32_t i = 0; i < fcount; i++) {
        if (ppos + 4 > plainSize) return false;
        uint32_t nameLen = readU32LE(plain + ppos); ppos += 4;
        if (ppos + nameLen > plainSize) return false;
        std::string name(reinterpret_cast<const char*>(plain + ppos), nameLen); ppos += nameLen;

        if (ppos + 4 > plainSize) return false;
        uint32_t dataLen = readU32LE(plain + ppos); ppos += 4;
        if (ppos + dataLen > plainSize) return false;
        std::string data(reinterpret_cast<const char*>(plain + ppos), dataLen); ppos += dataLen;

        g_resourceFiles[name] = std::move(data);
    }

    return true;
}

static duk_ret_t native_print(duk_context* ctx, std::ostream& out) {
    int n = duk_get_top(ctx);
    for (int i = 0; i < n; i++) {
        if (i > 0) out << ' ';
        out << duk_safe_to_string(ctx, i);
    }
    out << '\n';
    return 0;
}

static duk_ret_t js_console_log(duk_context* ctx)   { return native_print(ctx, std::cout); }
static duk_ret_t js_console_error(duk_context* ctx) { return native_print(ctx, std::cerr); }
static duk_ret_t js_console_warn(duk_context* ctx)  { return native_print(ctx, std::cerr); }

static void setupConsole(duk_context* ctx) {
    duk_push_global_object(ctx);
    duk_push_object(ctx);

    duk_push_c_function(ctx, js_console_log,   DUK_VARARGS);
    duk_put_prop_string(ctx, -2, "log");

    duk_push_c_function(ctx, js_console_log,   DUK_VARARGS);
    duk_put_prop_string(ctx, -2, "info");

    duk_push_c_function(ctx, js_console_error, DUK_VARARGS);
    duk_put_prop_string(ctx, -2, "error");

    duk_push_c_function(ctx, js_console_warn,  DUK_VARARGS);
    duk_put_prop_string(ctx, -2, "warn");

    duk_put_prop_string(ctx, -2, "console");
    duk_pop(ctx);
}

static const char* CACHE_KEY = "\xff" "moduleCache";

static void ensureCache(duk_context* ctx) {
    duk_push_heap_stash(ctx);
    if (!duk_has_prop_string(ctx, -1, CACHE_KEY)) {
        duk_push_object(ctx);
        duk_put_prop_string(ctx, -2, CACHE_KEY);
    }
    duk_pop(ctx);
}

static bool getCached(duk_context* ctx, const std::string& key) {
    duk_push_heap_stash(ctx);
    duk_get_prop_string(ctx, -1, CACHE_KEY);
    if (duk_get_prop_string(ctx, -1, key.c_str())) {
        duk_replace(ctx, -3);
        duk_pop(ctx);
        return true;
    }
    duk_pop_3(ctx);
    return false;
}

// Caches the value currently on top of the stack; stack layout unchanged.
static void putCache(duk_context* ctx, const std::string& key) {
    duk_push_heap_stash(ctx);
    duk_get_prop_string(ctx, -1, CACHE_KEY);
    duk_dup(ctx, -3);
    duk_put_prop_string(ctx, -2, key.c_str());
    duk_pop_2(ctx);
}

static std::string normaliseResourcePath(const std::string& id) {
    if (id.rfind("./", 0) == 0) return id;
    if (id.rfind("/", 0) == 0)  return "." + id;
    return "./" + id;
}

static std::string resolveResourceModule(const std::string& id, const std::string& baseDir) {
    auto tryKey = [](const std::string& k) -> std::string {
        if (g_resourceFiles.count(k)) return k;
        std::string withJs = k;
        if (withJs.size() < 3 || withJs.substr(withJs.size()-3) != ".js")
            withJs += ".js";
        if (g_resourceFiles.count(withJs)) return withJs;
        std::string indexKey = k;
        if (!indexKey.empty() && indexKey.back() != '/') indexKey += "/";
        indexKey += "index.js";
        if (g_resourceFiles.count(indexKey)) return indexKey;
        return {};
    };

    auto normalizePath = [](const std::string& p) -> std::string {
        std::vector<std::string> parts;
        std::string seg;
        std::istringstream ss(p);
        while (std::getline(ss, seg, '/')) {
            if (seg.empty() || seg == ".") continue;
            if (seg == "..") {
                if (!parts.empty()) parts.pop_back();
            } else {
                parts.push_back(seg);
            }
        }
        std::string result = "./";
        for (size_t i = 0; i < parts.size(); i++) {
            if (i > 0) result += '/';
            result += parts[i];
        }
        return result;
    };

    std::string base = baseDir;
    if (base.empty() || base == ".") base = "";
    else if (base.back() != '/') base += '/';

    std::string resolved;
    if (id.rfind("./", 0) == 0 || id.rfind("../", 0) == 0) {
        resolved = tryKey(normalizePath(base + id));
    } else {
        resolved = tryKey(normalizePath(base + "./" + id));
        if (resolved.empty())
            resolved = tryKey("./" + id);
    }

    if (resolved.empty())
        throw std::runtime_error("Cannot find module in resource: '" + id + "'");
    return resolved;
}

static fs::path resolveFileModule(const std::string& id, const fs::path& baseDir) {
    auto tryExtensions = [](fs::path p) -> fs::path {
        if (fs::exists(p) && fs::is_regular_file(p)) return p;
        if (fs::exists(fs::path(p).replace_extension(".js")))
            return fs::path(p).replace_extension(".js");
        fs::path indexPath = p / "index.js";
        if (fs::exists(indexPath)) return indexPath;
        return {};
    };

    fs::path candidate;
    if (id.rfind("./", 0) == 0 || id.rfind("../", 0) == 0 || id.rfind("/", 0) == 0) {
        candidate = tryExtensions(baseDir / id);
    } else {
        candidate = tryExtensions(baseDir / id);
        if (candidate.empty())
            candidate = tryExtensions(baseDir / "node_modules" / id);
    }

    if (candidate.empty())
        throw std::runtime_error("Cannot find module: '" + id + "' (from " + baseDir.string() + ")");

    return fs::canonical(candidate);
}

static bool executeModuleSource(duk_context* ctx,
                                 const std::string& src,
                                 const std::string& filename,
                                 const std::string& dirname,
                                 const std::string& cacheKey);

static duk_ret_t js_require(duk_context* ctx) {
    const char* id = duk_require_string(ctx, 0);

    if (g_resourceMode) {
        std::string baseDir = g_resourceDirStack.empty()
            ? std::string(".")
            : g_resourceDirStack.back();

        std::string modKey;
        try {
            modKey = resolveResourceModule(id, baseDir);
        } catch (const std::exception& e) {
            duk_error(ctx, DUK_ERR_ERROR, "%s", e.what());
            return 0;
        }

        if (getCached(ctx, modKey)) return 1;

        const std::string& src = g_resourceFiles.at(modKey);

        std::string dirname;
        size_t slash = modKey.rfind('/');
        if (slash != std::string::npos) dirname = modKey.substr(0, slash);
        else dirname = ".";

        g_resourceDirStack.push_back(dirname);
        bool ok = executeModuleSource(ctx, src, modKey, dirname, modKey);
        g_resourceDirStack.pop_back();

        if (!ok) {
            duk_error(ctx, DUK_ERR_ERROR, "Failed to load module: %s", modKey.c_str());
            return 0;
        }
        return 1;
    }

    fs::path baseDir = g_dirStack.empty() ? fs::current_path() : g_dirStack.back();

    fs::path modPath;
    try {
        modPath = resolveFileModule(id, baseDir);
    } catch (const std::exception& e) {
        duk_error(ctx, DUK_ERR_ERROR, "%s", e.what());
        return 0;
    }

    std::string cacheKey = fs::weakly_canonical(modPath).string();
    if (getCached(ctx, cacheKey)) return 1;

    std::string src;
    try {
        src = readFile(modPath);
    } catch (const std::exception& e) {
        duk_error(ctx, DUK_ERR_ERROR, "%s", e.what());
        return 0;
    }

    std::string filename = modPath.string();
    std::string dirname  = modPath.parent_path().string();

    g_dirStack.push_back(modPath.parent_path());
    bool ok = executeModuleSource(ctx, src, filename, dirname, cacheKey);
    g_dirStack.pop_back();

    if (!ok) {
        duk_error(ctx, DUK_ERR_ERROR, "Failed to load module: %s", filename.c_str());
        return 0;
    }
    return 1;
}

static bool executeModuleSource(duk_context* ctx,
                                 const std::string& src,
                                 const std::string& filename,
                                 const std::string& dirname,
                                 const std::string& cacheKey)
{
    ensureCache(ctx);

    std::string wrapped =
        "(function(module, exports, require, __filename, __dirname) {\n" +
        src + "\n})";

    duk_push_object(ctx);
    duk_push_object(ctx);
    duk_dup(ctx, -1);
    duk_put_prop_string(ctx, -3, "exports");

    putCache(ctx, cacheKey);

    if (duk_peval_string(ctx, wrapped.c_str()) != 0) {
        std::cerr << "[CryoJS] Compile error in " << filename << ": "
                  << duk_safe_to_string(ctx, -1) << '\n';
        duk_pop(ctx);
        duk_pop_2(ctx);
        return false;
    }

    duk_dup(ctx, -3);
    duk_dup(ctx, -3);
    duk_push_global_object(ctx);
    duk_get_prop_string(ctx, -1, "require");
    duk_remove(ctx, -2);
    duk_push_string(ctx, filename.c_str());
    duk_push_string(ctx, dirname.c_str());

    if (duk_pcall(ctx, 5) != 0) {
        std::cerr << "[CryoJS] Runtime error in " << filename << ": "
                  << duk_safe_to_string(ctx, -1) << '\n';
        duk_pop(ctx);
        duk_pop_2(ctx);
        return false;
    }

    duk_pop(ctx);

    duk_get_prop_string(ctx, -2, "exports");
    duk_replace(ctx, -2);
    putCache(ctx, cacheKey);

    return true;
}

static void setupRequire(duk_context* ctx) {
    duk_push_global_object(ctx);
    duk_push_c_function(ctx, js_require, 1);
    duk_put_prop_string(ctx, -2, "require");
    duk_pop(ctx);
}

static bool executeFile(duk_context* ctx, const fs::path& filePath) {
    std::string src;
    try {
        src = readFile(filePath);
    } catch (const std::exception& e) {
        std::cerr << "[CryoJS] " << e.what() << '\n';
        return false;
    }

    fs::path absPath = fs::absolute(filePath);
    g_dirStack.push_back(absPath.parent_path());

    duk_push_string(ctx, src.c_str());
    duk_push_string(ctx, absPath.string().c_str());

    if (duk_pcompile(ctx, 0) != 0) {
        g_dirStack.pop_back();
        std::cerr << "[CryoJS] Compile error: " << duk_safe_to_string(ctx, -1) << '\n';
        duk_pop(ctx);
        return false;
    }

    if (duk_pcall(ctx, 0) != 0) {
        g_dirStack.pop_back();
        if (duk_is_error(ctx, -1)) {
            duk_get_prop_string(ctx, -1, "stack");
            std::cerr << "[CryoJS] " << duk_safe_to_string(ctx, -1) << '\n';
            duk_pop(ctx);
        } else {
            std::cerr << "[CryoJS] Runtime error: " << duk_safe_to_string(ctx, -1) << '\n';
        }
        duk_pop(ctx);
        return false;
    }

    g_dirStack.pop_back();
    duk_pop(ctx);
    return true;
}

static bool executeResource(duk_context* ctx, const std::string& entryPoint) {
    std::string key;
    try {
        key = resolveResourceModule(entryPoint, ".");
    } catch (const std::exception& e) {
        std::cerr << "[CryoJS] " << e.what() << '\n';
        return false;
    }

    const std::string& src = g_resourceFiles.at(key);

    std::string dirname;
    size_t slash = key.rfind('/');
    if (slash != std::string::npos) dirname = key.substr(0, slash);
    else dirname = ".";

    duk_push_string(ctx, src.c_str());
    duk_push_string(ctx, key.c_str());

    if (duk_pcompile(ctx, 0) != 0) {
        std::cerr << "[CryoJS] Compile error in " << key << ": "
                  << duk_safe_to_string(ctx, -1) << '\n';
        duk_pop(ctx);
        return false;
    }

    g_resourceDirStack.push_back(dirname);

    if (duk_pcall(ctx, 0) != 0) {
        g_resourceDirStack.pop_back();
        if (duk_is_error(ctx, -1)) {
            duk_get_prop_string(ctx, -1, "stack");
            std::cerr << "[CryoJS] " << duk_safe_to_string(ctx, -1) << '\n';
            duk_pop(ctx);
        } else {
            std::cerr << "[CryoJS] Runtime error: " << duk_safe_to_string(ctx, -1) << '\n';
        }
        duk_pop(ctx);
        return false;
    }

    g_resourceDirStack.pop_back();
    duk_pop(ctx);
    return true;
}

static duk_ret_t js_process_exit(duk_context* ctx) {
    int code = duk_is_number(ctx, 0) ? static_cast<int>(duk_get_int(ctx, 0)) : 0;
    std::exit(code);
}

static duk_ret_t js_process_cwd(duk_context* ctx) {
    try {
        std::string cwd = fs::current_path().string();
        duk_push_string(ctx, cwd.c_str());
    } catch (...) {
        duk_push_string(ctx, ".");
    }
    return 1;
}

static void setupProcess(duk_context* ctx, const std::vector<std::string>& procArgv) {
    duk_push_global_object(ctx);
    duk_push_object(ctx);

    duk_push_array(ctx);
    for (size_t i = 0; i < procArgv.size(); i++) {
        duk_push_string(ctx, procArgv[i].c_str());
        duk_put_prop_index(ctx, -2, static_cast<duk_uarridx_t>(i));
    }
    duk_put_prop_string(ctx, -2, "argv");

    duk_push_c_function(ctx, js_process_exit, 1);
    duk_put_prop_string(ctx, -2, "exit");

    duk_push_c_function(ctx, js_process_cwd, 0);
    duk_put_prop_string(ctx, -2, "cwd");

    duk_put_prop_string(ctx, -2, "process");
    duk_pop(ctx);
}

static void printUsage() {
    std::cout << "Usage:\n";
    std::cout << "  CryoJS <script.js>                              Run a JS file\n";
    std::cout << "  CryoJS <archive.resource> <password> [entry]    Run encrypted resource\n";
    std::cout << "         entry defaults to ./main.js if omitted\n";
    std::cout << "  CryoJS -h | --help                              Show this help\n";
    std::cout << "  CryoJS --version                                Show version\n";
}

int main(int argc, char* argv[]) {
    if (argc >= 2) {
        std::string flag = argv[1];
        if (flag == "-h" || flag == "--help") {
            printUsage();
            return 0;
        }
        if (flag == "--version") {
            std::cout << "CryoJS " << CRYOJS_VERSION << '\n';
            return 0;
        }
    }

    if (argc < 2) {
        printUsage();
        return 1;
    }

    std::string arg1 = argv[1];
    bool isResource = arg1.size() > 9 &&
                      arg1.substr(arg1.size() - 9) == ".resource";

    duk_context* ctx = duk_create_heap_default();
    if (!ctx) {
        std::cerr << "[CryoJS] Failed to create Duktape heap\n";
        return 1;
    }

    ensureCache(ctx);
    setupConsole(ctx);
    setupRequire(ctx);

    std::vector<std::string> procArgv;
    procArgv.push_back(argv[0]);
    if (isResource) {
        procArgv.push_back(arg1);
    } else {
        for (int i = 1; i < argc; i++)
            procArgv.push_back(argv[i]);
    }
    setupProcess(ctx, procArgv);

    bool ok = false;

    if (isResource) {
        if (argc < 3) {
            std::cerr << "[CryoJS] Password required for .resource files\n";
            printUsage();
            duk_destroy_heap(ctx);
            return 1;
        }
        std::string password  = argv[2];
        std::string entryPoint = (argc >= 4) ? argv[3] : "./main.js";

        g_resourceMode = true;
        if (!loadResource(arg1, password)) {
            duk_destroy_heap(ctx);
            return 1;
        }

        ok = executeResource(ctx, entryPoint);
    } else {
        fs::path scriptPath = arg1;
        if (!fs::exists(scriptPath)) {
            std::cerr << "[CryoJS] File not found: " << scriptPath << '\n';
            duk_destroy_heap(ctx);
            return 1;
        }
        ok = executeFile(ctx, scriptPath);
    }

    duk_destroy_heap(ctx);
    return ok ? 0 : 1;
}
