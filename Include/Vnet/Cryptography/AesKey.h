/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_AESKEY_H_
#define _VNETSEC_CRYPTOGRAPHY_AESKEY_H_

#include <Vnet/Cryptography/SymmetricKey.h>

namespace Vnet::Cryptography {

    /**
     * Represents an AES key and an initialization vector (IV).
     */
    class VNETSECURITYAPI AesKey : public SymmetricKey {

    private:
        AesKey(std::vector<std::uint8_t>&& key, std::optional<std::vector<std::uint8_t>>&& iv);

    public:
        AesKey(AesKey&& key) noexcept;
        virtual ~AesKey(void);

        AesKey& operator= (AesKey&& key) noexcept;
        bool operator== (const AesKey& key) const;
        virtual bool operator== (const SymmetricKey& key) const override;

        /**
         * Imports an AES key and an initialization vector (IV).
         * 
         * @param key 128/192/256 bit AES key.
         * @param iv 128 bit initialization vector (IV).
         * @returns A newly created AesKey object.
         * @exception std::invalid_argument - The 'key' parameter contains a key of an invalid size,
         * or the 'iv' parameter contains an initialization vector of an invalid size.
         */
        static AesKey Import(const std::span<const std::uint8_t> key, const std::optional<std::span<const std::uint8_t>> iv);

        /**
         * Generates a new AES key and a new initialization vector (IV).
         * 
         * @param keySize The key size (in bits).
         * @returns A newly created AesKey object.
         * @exception std::invalid_argument - The 'keySize' paremeter contains an invalid size for an AES key.
         * @exception SecurityException - Key generation failed.
         */
        static AesKey Generate(const std::int32_t keySize);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_AESKEY_H_