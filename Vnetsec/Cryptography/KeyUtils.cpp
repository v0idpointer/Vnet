/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Cryptography/KeyUtils.h>
#include <Vnet/Security/SecurityException.h>

#include <Vnet/Cryptography/RsaKey.h>
#include <Vnet/Cryptography/AesKey.h>

using namespace Vnet::Cryptography;
using namespace Vnet::Security;

std::unique_ptr<CryptoKey> KeyUtils::DuplicateKey(const CryptoKey& key) {

    // RSA key:
    if (const RsaKey* pKey = dynamic_cast<const RsaKey*>(&key))
        return std::make_unique<RsaKey>(RsaKey::ImportParameters(pKey->ExportParameters()));

    // AES key:
    if (const AesKey* pKey = dynamic_cast<const AesKey*>(&key))
        return std::make_unique<AesKey>(AesKey::Import(pKey->GetKey(), pKey->GetIv()));

    // add other key types here.

    throw std::runtime_error("Unknown key type.");
}

std::unique_ptr<CryptoKey> KeyUtils::ImportPEM(const std::string_view pem, const std::optional<std::string_view> password) {
    
    if (pem.empty()) throw std::invalid_argument("'pem': Empty string.");

    // RSA key:
    try { return std::make_unique<RsaKey>(RsaKey::ImportPEM(pem, password)); }
    catch (const std::runtime_error&) { }
    
    // add other key types here.

    throw std::runtime_error("Unknown key type.");
}

bool KeyUtils::IsSymmetricKey(const CryptoKey& key) noexcept {
    return (dynamic_cast<const SymmetricKey*>(&key) != nullptr);
}