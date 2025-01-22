/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Cryptography/SHA1.h>
#include <Vnet/Security/SecurityException.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>

using namespace Vnet::Cryptography;
using namespace Vnet::Security;

std::vector<std::uint8_t> SHA1::Digest(const std::span<const std::uint8_t> data) {

    std::vector<std::uint8_t> digest((SHA1::DIGEST_SIZE / 8));
    SHA1::Digest(data, digest);

    return digest;
}

void SHA1::Digest(const std::span<const std::uint8_t> data, const std::span<std::uint8_t> digest) {

    if (digest.size() < (SHA1::DIGEST_SIZE / 8))
        throw std::invalid_argument("'digest': Buffer too small.");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) throw SecurityException(ERR_get_error());

    if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    std::uint32_t size = digest.size();

    if (EVP_DigestFinal_ex(ctx, digest.data(), &size) != 1) {
        EVP_MD_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    EVP_MD_CTX_free(ctx);

}