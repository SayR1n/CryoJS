#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <stdexcept>
#include <algorithm>

#include "aes.h"
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
    std::vector<uint8_t> out(n);
    for (size_t i = 0; i < n; i++)
        out[i] = static_cast<uint8_t>(rand() & 0xFF);
    return out;
}

static std::vector<FileEntry> collectFiles(const fs::path& rootDir) {
    std::vector<FileEntry> files;
    for (auto& entry : fs::recursive_directory_iterator(rootDir)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".js") continue;

        std::string rel = fs::relative(entry.path(), rootDir).generic_string();
        if (rel.rfind("./", 0) != 0) rel = "./" + rel;

        std::ifstream f(entry.path(), std::ios::binary);
        if (!f) throw std::runtime_error("Cannot open: " + entry.path().string());
        std::string src((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

        FileEntry fe;
        fe.name = rel;
        fe.data.assign(src.begin(), src.end());
        files.push_back(std::move(fe));
    }
    std::sort(files.begin(), files.end(), [](const FileEntry& a, const FileEntry& b) {
        return a.name < b.name;
    });
    return files;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: cryopack <input_dir> <output.resource> <password>\n";
        return 1;
    }

    fs::path inputDir   = argv[1];
    fs::path outputFile = argv[2];
    std::string password = argv[3];

    if (!fs::is_directory(inputDir)) {
        std::cerr << "[cryopack] Not a directory: " << inputDir << '\n';
        return 1;
    }

    srand(static_cast<unsigned>(time(nullptr)));

    std::vector<FileEntry> files;
    try {
        files = collectFiles(inputDir);
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
    auto padding = randomBytes(12);

    uint8_t key[KEY_SIZE];
    deriveKey(password, salt.data(), key);

    std::vector<uint8_t> plain  = buildPlaintext(files);
    std::vector<uint8_t> padded = pkcs7Pad(plain);

    struct AES_ctx aesCtx;
    AES_init_ctx_iv(&aesCtx, key, iv.data());
    AES_CBC_encrypt_buffer(&aesCtx, padded.data(), padded.size());

    std::vector<uint8_t> out;
    appendBytes(out, MAGIC, 4);
    appendBytes(out, padding.data(), padding.size());

    uint32_t fileCountObf = static_cast<uint32_t>(files.size()) ^ XOR_MASK;
    appendU32LE(out, fileCountObf);
    appendBytes(out, salt.data(), SALT_SIZE);
    appendBytes(out, iv.data(), IV_SIZE);
    appendU32LE(out, static_cast<uint32_t>(padded.size()));
    appendBytes(out, padded.data(), padded.size());

    for (size_t i = 4; i < out.size(); i++)
        out[i] ^= MAGIC[i % 4];

    std::ofstream ofs(outputFile, std::ios::binary);
    if (!ofs) {
        std::cerr << "[cryopack] Cannot create: " << outputFile << '\n';
        return 1;
    }
    ofs.write(reinterpret_cast<char*>(out.data()), out.size());

    std::cout << "[cryopack] Done -> " << outputFile
              << " (" << out.size() << " bytes)\n";
    return 0;
}
