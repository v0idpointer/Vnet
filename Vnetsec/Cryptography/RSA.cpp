/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Cryptography/RSA.h>
#include <Vnet/Security/SecurityException.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace Vnet::Cryptography;
using namespace Vnet::Security;

std::vector<std::uint8_t> Vnet::Cryptography::RSA::Encrypt(const RsaKey& key, const std::span<const std::uint8_t> data) {

    if (key.GetNativeKeyHandle() == INVALID_KEY_HANDLE)
        throw std::invalid_argument("'key': Invalid key.");

    const ::RSA* rsa = EVP_PKEY_get0_RSA(key.GetNativeKeyHandle());
    if (rsa == nullptr) throw SecurityException(ERR_get_error());

    std::vector<std::uint8_t> encrypted(RSA_size(rsa));

    std::int32_t result = RSA_public_encrypt(data.size(), data.data(), encrypted.data(), const_cast<::RSA*>(rsa), RSA_PKCS1_OAEP_PADDING);
    if (result == -1) throw SecurityException(ERR_get_error());

    encrypted.resize(result);

    return encrypted;
}

std::vector<std::uint8_t> Vnet::Cryptography::RSA::Decrypt(const RsaKey& privateKey, const std::span<const std::uint8_t> encryptedData) {
    
    if (privateKey.GetNativeKeyHandle() == INVALID_KEY_HANDLE)
        throw std::invalid_argument("'privateKey': Invalid key.");

    if (!privateKey.IsPrivateKey())
        throw std::invalid_argument("'privateKey': The specified key is not an RSA private key.");

    const ::RSA* rsa = EVP_PKEY_get0_RSA(privateKey.GetNativeKeyHandle());
    if (rsa == nullptr) throw SecurityException(ERR_get_error());

    std::vector<std::uint8_t> data(RSA_size(rsa));

    std::int32_t result = RSA_private_decrypt(encryptedData.size(), encryptedData.data(), data.data(), const_cast<::RSA*>(rsa), RSA_PKCS1_OAEP_PADDING);
    if (result == -1) throw SecurityException(ERR_get_error());

    data.resize(result);

    return data;
}