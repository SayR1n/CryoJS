#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <cstring>

static constexpr uint8_t  MAGIC[4]   = { 0xC9, 0x7E, 0x4A, 0x11 };
static constexpr uint32_t XOR_MASK   = 0xDEADBEEF;
static constexpr size_t   SALT_SIZE  = 32;
static constexpr size_t   IV_SIZE    = 16;
static constexpr size_t   KEY_SIZE   = 32;
static constexpr int      KDF_ROUNDS = 100000;

struct FileEntry {
    std::string name;
    std::vector<uint8_t> data;
};

inline void deriveKey(const std::string& password,
                      const uint8_t* salt,
                      uint8_t* outKey)
{
    uint8_t buf[KEY_SIZE] = {};
    for (int i = 0; i < KEY_SIZE; i++)
        buf[i] = static_cast<uint8_t>(password[i % password.size()]) ^ salt[i % SALT_SIZE];

    for (int round = 0; round < KDF_ROUNDS; round++) {
        for (int i = 0; i < KEY_SIZE; i++) {
            buf[i] ^= salt[(i + round) % SALT_SIZE];
            buf[i]  = static_cast<uint8_t>((buf[i] << 1) | (buf[i] >> 7));
            buf[i] ^= static_cast<uint8_t>(round & 0xFF);
            buf[i] ^= buf[(i + 1) % KEY_SIZE];
        }
    }
    memcpy(outKey, buf, KEY_SIZE);
}
