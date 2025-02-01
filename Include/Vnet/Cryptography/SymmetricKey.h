/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_SYMMETRICKEY_H_
#define _VNETSEC_CRYPTOGRAPHY_SYMMETRICKEY_H_

#include <Vnet/Cryptography/CryptoKey.h>

#include <cstdint>
#include <vector>
#include <span>

namespace Vnet::Cryptography {

    /**
     * Base class for all symmetric cryptographic keys.
     */
    class VNETSECURITYAPI SymmetricKey : public CryptoKey {

    private:
        std::vector<std::uint8_t> m_symmetricKey;
        std::optional<std::vector<std::uint8_t>> m_initializationVector;

    protected:
        SymmetricKey(std::vector<std::uint8_t>&& key, std::optional<std::vector<std::uint8_t>>&& iv) noexcept;
        SymmetricKey(SymmetricKey&& key) noexcept;

        SymmetricKey& operator= (SymmetricKey&& key) noexcept;

    public:
        SymmetricKey(const SymmetricKey&) = delete;
        virtual ~SymmetricKey(void);

        SymmetricKey& operator= (const SymmetricKey&) = delete;
        virtual bool operator== (const SymmetricKey& key) const;
        virtual bool operator== (const CryptoKey& key) const override;

        /**
         * Returns the symmetric cryptographic key.
         */
        const std::vector<std::uint8_t>& GetKey(void) const;

        /**
         * Returns the initialization vector (IV).
         */
        const std::optional<std::vector<std::uint8_t>>& GetIv(void) const;

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_SYMMETRICKEY_H_