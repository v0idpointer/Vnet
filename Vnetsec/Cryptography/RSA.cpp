/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef VNET_BUILD_VNETSEC
#define VNET_BUILD_VNETSEC
#endif

#include <Vnet/Cryptography/RSA.h>
#include <Vnet/Security/SecurityException.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>

using namespace Vnet::Cryptography;
using namespace Vnet::Security;

const std::unordered_map<RsaEncryptionPadding, std::tuple<std::int32_t, const evp_md_st* (*)(void), const evp_md_st* (*)(void)>> Vnet::Cryptography::RSA::s_paddings = {
    
    { RsaEncryptionPadding::NO_PADDING, { RSA_NO_PADDING, nullptr, nullptr } },

    { RsaEncryptionPadding::PKCS1, { RSA_PKCS1_PADDING, nullptr, nullptr } },
    { RsaEncryptionPadding::PKCS1_OAEP_SHA1, { RSA_PKCS1_OAEP_PADDING, &EVP_sha1, &EVP_sha1 } },
    { RsaEncryptionPadding::PKCS1_OAEP_SHA256, { RSA_PKCS1_OAEP_PADDING, &EVP_sha256, &EVP_sha256 } },
    { RsaEncryptionPadding::PKCS1_OAEP_SHA512, { RSA_PKCS1_OAEP_PADDING, &EVP_sha512, &EVP_sha512 } },

};

std::vector<std::uint8_t> Vnet::Cryptography::RSA::Encrypt(const RsaKey& key, const std::span<const std::uint8_t> data, const RsaEncryptionPadding padding) {

    if (key.GetNativeKeyHandle() == INVALID_KEY_HANDLE)
        throw std::invalid_argument("'key': Invalid key.");

    if (!RSA::s_paddings.contains(padding))
        throw std::invalid_argument("'padding': Invalid padding.");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key.GetNativeKeyHandle(), nullptr);
    if (ctx == nullptr) throw SecurityException(ERR_get_error());

    if (EVP_PKEY_encrypt_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    const auto [paddingMode, oaep, mgf1] = RSA::s_paddings.at(padding);

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, paddingMode) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    if (oaep && (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaep()) != 1)) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    if (mgf1 && (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1())!= 1)) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }
    
    std::vector<std::uint8_t> encrypted;
    std::size_t size = 0;

    if (EVP_PKEY_encrypt(ctx, nullptr, &size, data.data(), data.size()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    encrypted.resize(size);

    if (EVP_PKEY_encrypt(ctx, encrypted.data(), &size, data.data(), data.size()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    EVP_PKEY_CTX_free(ctx);

    return encrypted;
}

std::vector<std::uint8_t> Vnet::Cryptography::RSA::Decrypt(const RsaKey& privateKey, const std::span<const std::uint8_t> encryptedData, const RsaEncryptionPadding padding) {
    
    if (privateKey.GetNativeKeyHandle() == INVALID_KEY_HANDLE)
        throw std::invalid_argument("'privateKey': Invalid key.");

    if (!privateKey.IsPrivateKey())
        throw std::invalid_argument("'privateKey': The specified key is not an RSA private key.");

    if (!RSA::s_paddings.contains(padding))
        throw std::invalid_argument("'padding': Invalid padding.");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey.GetNativeKeyHandle(), nullptr);
    if (ctx == nullptr) throw SecurityException(ERR_get_error());

    if (EVP_PKEY_decrypt_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    const auto [paddingMode, oaep, mgf1] = RSA::s_paddings.at(padding);

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, paddingMode) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    if (oaep && (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, oaep()) != 1)) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    if (mgf1 && (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, mgf1()) != 1)) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    std::vector<std::uint8_t> data;
    std::size_t size = 0;

    if (EVP_PKEY_decrypt(ctx, nullptr, &size, encryptedData.data(), encryptedData.size()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    data.resize(size);

    if (EVP_PKEY_decrypt(ctx, data.data(), &size, encryptedData.data(), encryptedData.size()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    EVP_PKEY_CTX_free(ctx);

    return data;
}