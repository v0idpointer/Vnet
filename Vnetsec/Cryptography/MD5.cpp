/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Cryptography/MD5.h>
#include <Vnet/Security/SecurityException.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>

using namespace Vnet::Cryptography;
using namespace Vnet::Security;

std::vector<std::uint8_t> MD5::Digest(const std::span<const std::uint8_t> data) {

    std::vector<std::uint8_t> digest((MD5::DIGEST_SIZE / 8));
    MD5::Digest(data, digest);

    return digest;
}

void MD5::Digest(const std::span<const std::uint8_t> data, const std::span<std::uint8_t> digest) {

    if (digest.size() < (MD5::DIGEST_SIZE / 8))
        throw std::invalid_argument("'digest': Buffer too small.");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) throw SecurityException(ERR_get_error());

    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1) {
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