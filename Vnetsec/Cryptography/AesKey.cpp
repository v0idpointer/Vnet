/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Cryptography/AesKey.h>
#include <Vnet/Security/SecurityException.h>

#include <openssl/rand.h>
#include <openssl/err.h>

using namespace Vnet::Cryptography;
using namespace Vnet::Security;

AesKey::AesKey(std::vector<std::uint8_t>&& key, std::optional<std::vector<std::uint8_t>>&& iv) 
    : SymmetricKey(std::move(key), std::move(iv)) { }

AesKey::AesKey(AesKey&& key) noexcept : SymmetricKey({ }, std::nullopt) { 
    this->operator= (std::move(key));
}

AesKey::~AesKey() { }

AesKey& AesKey::operator= (AesKey&& key) noexcept {
    SymmetricKey::operator= (std::move(key));
    return static_cast<AesKey&>(*this);
}

bool AesKey::operator== (const AesKey& key) const {
    return SymmetricKey::operator== (key);
}

bool AesKey::operator== (const SymmetricKey& key) const {

    const AesKey* pKey = nullptr;
    if ((pKey = dynamic_cast<const AesKey*>(&key)) != nullptr)
        return AesKey::operator== (static_cast<const AesKey&>(*pKey));

    return false;
}

AesKey AesKey::Import(const std::span<const std::uint8_t> key, const std::optional<std::span<const std::uint8_t>> iv) {

    const std::int32_t keySize = (key.size() * 8);
    if ((keySize != 128) && (keySize != 192) && (keySize != 256))
        throw std::invalid_argument("'key': Invalid key size.");

    if (iv.has_value() && ((iv->size() * 8) != 128))
        throw std::invalid_argument("'iv': Invalid IV size.");

    std::vector<std::uint8_t> keyCopy = { key.begin(), key.end() };
    std::optional<std::vector<std::uint8_t>> ivCopy = std::nullopt;

    if (iv.has_value()) ivCopy = { iv->begin(), iv->end() };

    return { std::move(keyCopy), std::move(ivCopy) };
}

AesKey AesKey::Generate(const std::int32_t keySize) {

    if ((keySize != 128) && (keySize != 192) && (keySize != 256))
        throw std::invalid_argument("'keySize': Invalid key size.");

    std::vector<std::uint8_t> key((keySize / 8));
    std::vector<std::uint8_t> iv(16);

    if (RAND_bytes(key.data(), key.size()) != 1)
        throw SecurityException(ERR_get_error());

    if (RAND_bytes(iv.data(), iv.size()) != 1)
        throw SecurityException(ERR_get_error());

    return { std::move(key), std::move(iv) };
}