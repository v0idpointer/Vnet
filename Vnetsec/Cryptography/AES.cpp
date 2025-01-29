/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef VNET_BUILD_VNETSEC
#define VNET_BUILD_VNETSEC
#endif

#include <Vnet/Cryptography/AES.h>
#include <Vnet/Security/SecurityException.h>

#include <openssl/evp.h>
#include <openssl/err.h>

using namespace Vnet::Cryptography;
using namespace Vnet::Security;

namespace std {

    template <>
    struct std::hash<std::pair<std::int32_t, BlockCipherMode>> {

        std::size_t operator() (const std::pair<std::int32_t, BlockCipherMode>& p) const noexcept {
            const std::size_t h1 = std::hash<std::int32_t>{ } (p.first);
            const std::size_t h2 = std::hash<std::int32_t>{ } (static_cast<std::int32_t>(p.second));
            return (h1 ^ (h2 << 1));
        }

    };

}

const std::unordered_map<std::pair<std::int32_t, BlockCipherMode>, const evp_cipher_st* (*)(void)> AES::s_ciphers = { 

    { { 128, BlockCipherMode::CBC }, &EVP_aes_128_cbc },
    { { 192, BlockCipherMode::CBC }, &EVP_aes_192_cbc },
    { { 256, BlockCipherMode::CBC }, &EVP_aes_256_cbc },

};

static inline std::int32_t GetCiphertextSize(const std::int32_t blockSize, const std::int32_t plaintextLen) noexcept {
    const std::int32_t padding = (blockSize - (plaintextLen % blockSize));
    return (plaintextLen + padding);
}

std::vector<std::uint8_t> AES::Encrypt(
    const std::span<const std::uint8_t> key, 
    const std::optional<std::span<const std::uint8_t>> iv, 
    const std::span<const std::uint8_t> data,
    const BlockCipherMode mode
) {
    
    const std::int32_t keySize = (key.size() * 8);
    if ((keySize != 128) && (keySize != 192) && (keySize != 256))
        throw std::invalid_argument("'key': Invalid key size.");

    if (iv.has_value() && ((iv->size() * 8) != 128))
        throw std::invalid_argument("'iv': Invalid IV size.");

    if (!AES::s_ciphers.contains({ keySize, mode }))
        throw std::invalid_argument("'mode': Invalid/unsupported block cipher mode.");

    if (!iv.has_value())
        throw std::invalid_argument("'iv': std::nullopt");

    const EVP_CIPHER* cipher = AES::s_ciphers.at({ keySize, mode })();
    const std::uint8_t* pIV = (iv.has_value() ? iv->data() : nullptr);
    const std::int32_t blockSize = EVP_CIPHER_get_block_size(cipher);

    if ((data.size() % blockSize) != 0)
        throw std::invalid_argument("'data': Data not padded.");

    std::int32_t len = 0, totalLen = 0;
    std::vector<std::uint8_t> encrypted(GetCiphertextSize(blockSize, data.size()));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw SecurityException(ERR_get_error());

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), pIV) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    totalLen += len;

    if (EVP_EncryptFinal_ex(ctx, (encrypted.data() + totalLen), &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    totalLen += len;
    EVP_CIPHER_CTX_free(ctx);

    encrypted.resize(totalLen);
    return encrypted;
}

std::vector<std::uint8_t> AES::Decrypt(
    const std::span<const std::uint8_t> key,
    const std::optional<std::span<const std::uint8_t>> iv,
    const std::span<const std::uint8_t> encryptedData,
    const BlockCipherMode mode
) {

    const std::int32_t keySize = (key.size() * 8);
    if ((keySize != 128) && (keySize != 192) && (keySize != 256))
        throw std::invalid_argument("'key': Invalid key size.");

    if (iv.has_value() && ((iv->size() * 8) != 128))
        throw std::invalid_argument("'iv': Invalid IV size.");

    if (!AES::s_ciphers.contains({ keySize, mode }))
        throw std::invalid_argument("'mode': Invalid/unsupported block cipher mode.");

    if (!iv.has_value())
        throw std::invalid_argument("'iv': std::nullopt");

    const EVP_CIPHER* cipher = AES::s_ciphers.at({ keySize, mode })();
    const std::uint8_t* pIV = (iv.has_value() ? iv->data() : nullptr);
    const std::int32_t blockSize = EVP_CIPHER_get_block_size(cipher);

    if ((encryptedData.size() % blockSize) != 0)
        throw std::invalid_argument("'encryptedData': Incomplete block.");

    std::int32_t len = 0, totalLen = 0;
    std::vector<std::uint8_t> decrypted(GetCiphertextSize(blockSize, encryptedData.size()));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) throw SecurityException(ERR_get_error());

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), pIV) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, encryptedData.data(), encryptedData.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    totalLen += len;

    if (EVP_DecryptFinal_ex(ctx, (decrypted.data() + totalLen), &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    totalLen += len;
    EVP_CIPHER_CTX_free(ctx);

    decrypted.resize(totalLen);
    return decrypted;
}