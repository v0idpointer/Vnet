/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef VNET_BUILD_VNETSEC
#define VNET_BUILD_VNETSEC
#endif

#include <Vnet/Cryptography/RSA.h>
#include <Vnet/Cryptography/HashFunction.h>
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
    { RsaEncryptionPadding::PKCS1_OAEP_SHA224, { RSA_PKCS1_OAEP_PADDING, &EVP_sha224, &EVP_sha224 } },
    { RsaEncryptionPadding::PKCS1_OAEP_SHA256, { RSA_PKCS1_OAEP_PADDING, &EVP_sha256, &EVP_sha256 } },
    { RsaEncryptionPadding::PKCS1_OAEP_SHA384, { RSA_PKCS1_OAEP_PADDING, &EVP_sha384, &EVP_sha384 } },
    { RsaEncryptionPadding::PKCS1_OAEP_SHA512, { RSA_PKCS1_OAEP_PADDING, &EVP_sha512, &EVP_sha512 } },
    { RsaEncryptionPadding::PKCS1_OAEP_SHA3_224, { RSA_PKCS1_OAEP_PADDING, &EVP_sha3_224, &EVP_sha3_224 } },
    { RsaEncryptionPadding::PKCS1_OAEP_SHA3_256, { RSA_PKCS1_OAEP_PADDING, &EVP_sha3_256, &EVP_sha3_256 } },
    { RsaEncryptionPadding::PKCS1_OAEP_SHA3_384, { RSA_PKCS1_OAEP_PADDING, &EVP_sha3_384, &EVP_sha3_384 } },
    { RsaEncryptionPadding::PKCS1_OAEP_SHA3_512, { RSA_PKCS1_OAEP_PADDING, &EVP_sha3_512, &EVP_sha3_512 } },

};

const std::unordered_map<RsaSignaturePadding, std::int32_t> Vnet::Cryptography::RSA::s_signPaddings = { 

    { RsaSignaturePadding::PKCS1, RSA_PKCS1_PADDING },
    { RsaSignaturePadding::PSS, RSA_PKCS1_PSS_PADDING },

};

std::vector<std::uint8_t> Vnet::Cryptography::RSA::Encrypt(const RsaKey& key, const std::span<const std::uint8_t> data, const RsaEncryptionPadding padding) {

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

std::vector<std::uint8_t> Vnet::Cryptography::RSA::Sign(
    const RsaKey& privateKey, 
    const std::span<const std::uint8_t> data, 
    const HashAlgorithm hashAlg, 
    const RsaSignaturePadding padding
) { 
    return RSA::SignHashed(privateKey, HashFunction::Digest(hashAlg, data), hashAlg, padding); 
}

std::vector<std::uint8_t> Vnet::Cryptography::RSA::SignHashed(
    const RsaKey& privateKey, 
    const std::span<const std::uint8_t> hashedData, 
    const HashAlgorithm hashAlg, 
    const RsaSignaturePadding padding
) {

    if (!privateKey.IsPrivateKey())
        throw std::invalid_argument("'privateKey': The specified key is not an RSA private key.");

    if (!RSA::s_signPaddings.contains(padding))
        throw std::invalid_argument("'padding': Invalid padding.");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey.GetNativeKeyHandle(), nullptr);
    if (ctx == nullptr) throw SecurityException(ERR_get_error());

    if (EVP_PKEY_sign_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA::s_signPaddings.at(padding)) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, HashFunction::_GetOpensslEvpMd(hashAlg)) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    std::vector<std::uint8_t> signature;
    std::size_t size = 0;

    if (EVP_PKEY_sign(ctx, nullptr, &size, hashedData.data(), hashedData.size()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    signature.resize(size);

    if (EVP_PKEY_sign(ctx, signature.data(), &size, hashedData.data(), hashedData.size()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    EVP_PKEY_CTX_free(ctx);

    return signature;
}

bool Vnet::Cryptography::RSA::Verify(
    const RsaKey& key, 
    const std::span<const std::uint8_t> data, 
    const std::span<const std::uint8_t> signature, 
    const HashAlgorithm hashAlg, 
    const RsaSignaturePadding padding
) {
    return RSA::VerifyHashed(key, HashFunction::Digest(hashAlg, data), signature, hashAlg, padding);
}

bool Vnet::Cryptography::RSA::VerifyHashed(
    const RsaKey& key, 
    const std::span<const std::uint8_t> hashedData, 
    const std::span<const std::uint8_t> signature, 
    const HashAlgorithm hashAlg, 
    const RsaSignaturePadding padding
) {

    if (!RSA::s_signPaddings.contains(padding))
        throw std::invalid_argument("'padding': Invalid padding.");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key.GetNativeKeyHandle(), nullptr);
    if (ctx == nullptr) throw SecurityException(ERR_get_error());

    if (EVP_PKEY_verify_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA::s_signPaddings.at(padding)) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, HashFunction::_GetOpensslEvpMd(hashAlg)) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    std::int32_t result = EVP_PKEY_verify(ctx, signature.data(), signature.size(), hashedData.data(), hashedData.size());
    if (result < 0) {
        EVP_PKEY_CTX_free(ctx);
        throw SecurityException(ERR_get_error());
    }

    EVP_PKEY_CTX_free(ctx);

    return (result == 1);
}

RsaKey Vnet::Cryptography::RSA::GenerateKeyPair(const std::int32_t keySize) {
    return RsaKey::Generate(keySize);
}