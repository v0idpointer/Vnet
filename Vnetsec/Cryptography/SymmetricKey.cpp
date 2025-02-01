/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Cryptography/SymmetricKey.h>

#include <algorithm>

using namespace Vnet::Cryptography;

SymmetricKey::SymmetricKey(std::vector<std::uint8_t>&& key, std::optional<std::vector<std::uint8_t>>&& iv) noexcept
    : CryptoKey(INVALID_KEY_HANDLE), m_symmetricKey(std::move(key)), m_initializationVector(std::move(iv)) { }

SymmetricKey::SymmetricKey(SymmetricKey&& key) noexcept : CryptoKey(INVALID_KEY_HANDLE) {
    this->operator= (std::move(key));
}

SymmetricKey& SymmetricKey::operator= (SymmetricKey&& key) noexcept {

    if (this != &key) {
        this->m_symmetricKey = std::move(key.m_symmetricKey);
        this->m_initializationVector = std::move(key.m_initializationVector);
    }

    return static_cast<SymmetricKey&>(*this);
}

SymmetricKey::~SymmetricKey() { }

bool SymmetricKey::operator== (const SymmetricKey& key) const {

    if (this->m_symmetricKey.size() != key.m_symmetricKey.size()) return false;
    if (this->m_initializationVector.has_value() != key.m_initializationVector.has_value()) return false;

    const bool keysEqual = std::equal(
        this->m_symmetricKey.begin(),
        this->m_symmetricKey.end(),
        key.m_symmetricKey.begin(),
        key.m_symmetricKey.end()
    );

    bool ivsEqual = true;
    if (this->m_initializationVector.has_value())
        ivsEqual = std::equal(
            this->m_initializationVector->begin(),
            this->m_initializationVector->end(),
            key.m_initializationVector->begin(),
            key.m_initializationVector->end()
        );

    return (keysEqual && ivsEqual);
}

bool SymmetricKey::operator== (const CryptoKey& key) const {

    const SymmetricKey* pKey = nullptr;
    if ((pKey = dynamic_cast<const SymmetricKey*>(&key)) != nullptr)
        return this->operator== (static_cast<const SymmetricKey&>(*pKey));

    return false;
}

const std::vector<std::uint8_t>& SymmetricKey::GetKey() const {
    return this->m_symmetricKey;
}

const std::optional<std::vector<std::uint8_t>>& SymmetricKey::GetIv() const {
    return this->m_initializationVector;
}