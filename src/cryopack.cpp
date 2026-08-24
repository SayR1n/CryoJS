#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <random>
#include <filesystem>
#include <stdexcept>
#include <algorithm>

#include "aes.h"
#include "miniz.h"
#include "resource_format.h"

namespace fs = std::filesystem;

static void appendU32LE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(v & 0xFF);
    buf.push_back((v >> 8) & 0xFF);
    buf.push_back((v >> 16) & 0xFF);
    buf.push_back((v >> 24) & 0xFF);
}

static void appendBytes(std::vector<uint8_t>& buf, const uint8_t* data, size_t len) {
    buf.insert(buf.end(), data, data + len);
}

static std::vector<uint8_t> buildPlaintext(const std::vector<FileEntry>& files) {
    std::vector<uint8_t> plain;
    appendU32LE(plain, static_cast<uint32_t>(files.size()));

    for (const auto& f : files) {
        appendU32LE(plain, static_cast<uint32_t>(f.name.size()));
        appendBytes(plain, reinterpret_cast<const uint8_t*>(f.name.data()), f.name.size());
        appendU32LE(plain, static_cast<uint32_t>(f.data.size()));
        appendBytes(plain, f.data.data(), f.data.size());
    }

    uint32_t checksum = 0;
    for (auto b : plain) checksum = checksum * 31 + b;
    appendU32LE(plain, checksum);

    return plain;
}

static std::vector<uint8_t> pkcs7Pad(const std::vector<uint8_t>& data) {
    uint8_t pad = static_cast<uint8_t>(16 - (data.size() % 16));
    std::vector<uint8_t> padded = data;
    for (int i = 0; i < pad; i++) padded.push_back(pad);
    return padded;
}

static std::vector<uint8_t> randomBytes(size_t n) {
    static std::random_device rd;
    std::vector<uint8_t> out(n);
    for (size_t i = 0; i < n; i++)
        out[i] = static_cast<uint8_t>(rd());
    return out;
}

static bool matchesAny(const std::vector<std::string>& patterns, const std::string& s) {
    for (const auto& p : patterns)
        if (globMatch(p, s)) return true;
    return false;
}

// Directory match additionally tolerates a trailing '/' in the pattern ("build/").
static bool matchesAnyDir(const std::vector<std::string>& patterns, const std::string& s) {
    if (matchesAny(patterns, s)) return true;
    for (const auto& p : patterns) {
        std::string base = p;
        while (!base.empty() && base.back() == '/') base.pop_back();
        if (!base.empty() && globMatch(base, s)) return true;
    }
    return false;
}

static std::vector<std::string> loadIgnoreFile(const fs::path& rootDir) {
    std::vector<std::string> out;
    std::ifstream f(rootDir / ".cryopackignore");
    if (!f) return out;

    std::string line;
    while (std::getline(f, line)) {
        while (!line.empty() &&
               (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos) continue;
        line = line.substr(start);
        if (line[0] == '#') continue;
        out.push_back(line);
    }
    return out;
}

static std::vector<FileEntry> collectFiles(const fs::path& rootDir,
                                           const std::vector<std::string>& includes,
                                           const std::vector<std::string>& ignores)
{
    std::vector<FileEntry> files;
    fs::recursive_directory_iterator it(rootDir), end;
    for (; it != end; ++it) {
        const auto& entry = *it;
        fs::path relPath = fs::relative(entry.path(), rootDir);

        if (entry.is_directory()) {
            std::string name = entry.path().filename().string();
            if (matchesAnyDir(ignores, relPath.generic_string()) ||
                matchesAnyDir(ignores, name))
                it.disable_recursion_pending();
            continue;
        }

        if (!entry.is_regular_file()) continue;

        std::string name = entry.path().filename().string();
        std::string rel  = relPath.generic_string();

        if (matchesAny(ignores, rel) || matchesAny(ignores, name)) continue;
        if (!matchesAny(includes, name)) continue;

        std::ifstream f(entry.path(), std::ios::binary);
        if (!f) throw std::runtime_error("Cannot open: " + entry.path().string());
        std::string src((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

        FileEntry fe;
        fe.name = "./" + rel;
        fe.data.assign(src.begin(), src.end());
        files.push_back(std::move(fe));
    }
    std::sort(files.begin(), files.end(), [](const FileEntry& a, const FileEntry& b) {
        return a.name < b.name;
    });
    return files;
}

static void printUsage() {
    std::cerr << "Usage: cryopack <input_dir> <output.resource> <password> [options]\n";
    std::cerr << "\nOptions:\n";
    std::cerr << "  --include, -i <pattern>   Extra file glob to pack (default: *.js)\n";
    std::cerr << "  -h, --help                Show this help\n";
    std::cerr << "\nPatterns support * and ?. A .cryopackignore file in input_dir\n";
    std::cerr << "excludes matching files/directories (# starts a comment).\n";
}

int main(int argc, char* argv[]) {
    std::vector<std::string> positional;
    std::vector<std::string> includes{ "*.js" };

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            printUsage();
            return 0;
        } else if ((arg == "--include" || arg == "-i") && i + 1 < argc) {
            includes.push_back(argv[++i]);
        } else {
            positional.push_back(arg);
        }
    }

    if (positional.size() < 3) {
        printUsage();
        return 1;
    }

    fs::path inputDir   = positional[0];
    fs::path outputFile = positional[1];
    std::string password = positional[2];

    if (!fs::is_directory(inputDir)) {
        std::cerr << "[cryopack] Not a directory: " << inputDir << '\n';
        return 1;
    }

    std::vector<FileEntry> files;
    try {
        auto ignores = loadIgnoreFile(inputDir);
        files = collectFiles(inputDir, includes, ignores);
    } catch (const std::exception& e) {
        std::cerr << "[cryopack] " << e.what() << '\n';
        return 1;
    }

    if (files.empty()) {
        std::cerr << "[cryopack] No .js files found in " << inputDir << '\n';
        return 1;
    }

    std::cout << "[cryopack] Packing " << files.size() << " file(s):\n";
    for (const auto& f : files)
        std::cout << "  " << f.name << " (" << f.data.size() << " bytes)\n";

    auto salt    = randomBytes(SALT_SIZE);
    auto iv      = randomBytes(IV_SIZE);
    auto padding = randomBytes(10);

    uint8_t key[KEY_SIZE];
    deriveKey(password, salt.data(), key);

    std::vector<uint8_t> plain = buildPlaintext(files);

    uint8_t flags = 0;
    std::vector<uint8_t> payload;

    mz_ulong compCap = mz_compressBound(static_cast<mz_ulong>(plain.size()));
    std::vector<uint8_t> comp(static_cast<size_t>(compCap));
    mz_ulong compLen = compCap;

    int rc = mz_compress(comp.data(), &compLen, plain.data(),
                         static_cast<mz_ulong>(plain.size()));
    if (rc == MZ_OK && compLen > 0 && compLen < plain.size()) {
        flags |= FLAG_COMPRESSED;
        appendU32LE(payload, static_cast<uint32_t>(plain.size()));
        appendBytes(payload, comp.data(), compLen);
    } else {
        payload = plain;
    }

    std::vector<uint8_t> padded = pkcs7Pad(payload);

    struct AES_ctx aesCtx;
    AES_init_ctx_iv(&aesCtx, key, iv.data());
    AES_CBC_encrypt_buffer(&aesCtx, padded.data(), padded.size());

    std::vector<uint8_t> out;
    appendBytes(out, MAGIC_V2, 4);
    out.push_back(FORMAT_VERSION);
    out.push_back(flags);
    appendBytes(out, padding.data(), padding.size());

    uint32_t fileCountObf = static_cast<uint32_t>(files.size()) ^ XOR_MASK;
    appendU32LE(out, fileCountObf);
    appendBytes(out, salt.data(), SALT_SIZE);
    appendBytes(out, iv.data(), IV_SIZE);
    appendU32LE(out, static_cast<uint32_t>(padded.size()));
    appendBytes(out, padded.data(), padded.size());

    for (size_t i = 4; i < out.size(); i++)
        out[i] ^= MAGIC_V2[i % 4];

    std::ofstream ofs(outputFile, std::ios::binary);
    if (!ofs) {
        std::cerr << "[cryopack] Cannot create: " << outputFile << '\n';
        return 1;
    }
    ofs.write(reinterpret_cast<char*>(out.data()), out.size());

    std::cout << "[cryopack] Done -> " << outputFile
              << " (" << out.size() << " bytes";
    if (flags & FLAG_COMPRESSED)
        std::cout << ", compressed " << plain.size() << " -> "
                  << (payload.size() - 4) << " bytes";
    else
        std::cout << ", stored uncompressed";
    std::cout << ")\n";
    return 0;
}
