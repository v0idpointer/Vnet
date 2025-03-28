/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_AES_H_
#define _VNETSEC_CRYPTOGRAPHY_AES_H_

#include <Vnet/Cryptography/AesKey.h>
#include <Vnet/Cryptography/BlockCipherMode.h>

#include <unordered_map>
#include <unordered_set>

struct evp_cipher_st;

namespace Vnet::Cryptography {

    /**
     * Represents the AES (Advanced Encryption Standard) cryptographic algorithm.
     */
    class VNETSECURITYAPI AES final {

    private:
        static const std::unordered_map<std::pair<std::int32_t, BlockCipherMode>, const evp_cipher_st* (*)(void)> s_ciphers;
        static const std::unordered_set<BlockCipherMode> s_noIv;

    public:
        AES(void) = delete;

        /**
         * Encrypts the input data.
         * 
         * @param key The 128/192/256 bit AES key.
         * @param iv The 128 bit initialization vector (IV).
         * @param data The data to encrypt.
         * @param mode The block cipher mode of operation.
         * @returns The encrypted data.
         * @exception std::invalid_argument - The 'key' parameter contains a key of an invalid size,
         * or the 'iv' parameter contains an initialization vector of an invalid size,
         * or 'iv' is std::nullopt, or the input data is not padded,
         * or the 'mode' parameter contains an invalid/unsupported block cipher mode of operation.
         * @exception SecurityException - Encryption failed.
         */
        static std::vector<std::uint8_t> Encrypt(
            const std::span<const std::uint8_t> key,
            const std::optional<std::span<const std::uint8_t>> iv,
            const std::span<const std::uint8_t> data,
            const BlockCipherMode mode
        );

        /**
         * Encrypts the input data.
         * 
         * @param key The AES key and initialization vector (IV).
         * @param data The data to encrypt.
         * @param mode The block cipher mode of operation.
         * @returns The encrypted data.
         * @exception std::invalid_argument - The 'key' parameter does not have an initialization vector, 
         * or the input data is not padded, or the 'mode' parameter contains an invalid/unsupported block cipher mode of operation.
         * @exception SecurityException - Encryption failed.
         */
        static std::vector<std::uint8_t> Encrypt(
            const AesKey& key,
            const std::span<const std::uint8_t> data,
            const BlockCipherMode mode
        );

        /**
         * Decrypts the input data.
         * 
         * @param key The 128/192/256 bit AES key.
         * @param iv The 128 bit initialization vector (IV).
         * @param encryptedData The data to decrypt.
         * @param mode The block cipher mode of operation.
         * @returns The decrypted data.
         * @exception std::invalid_argument - The 'key' parameter contains a key of an invalid size,
         * or the 'iv' parameter contains an initialization vector of an invalid size,
         * or 'iv' is std::nullopt, or the input data does not form a complete block,
         * or the 'mode' parameter contains an invalid/unsupported block cipher mode of operation.
         * @exception SecurityException - Decryption failed.
         */
        static std::vector<std::uint8_t> Decrypt(
            const std::span<const std::uint8_t> key,
            const std::optional<std::span<const std::uint8_t>> iv,
            const std::span<const std::uint8_t> encryptedData,
            const BlockCipherMode mode
        );

        /**
         * Decrypts the input data.
         * 
         * @param key The AES key and initialization vector (IV).
         * @param encryptedData The data to decrypt.
         * @param mode The block cipher mode of operation.
         * @returns The decrypted data.
         * @exception std::invalid_argument - The 'key' parameter  does not have an initialization vector, 
         * or the input data does not form a complete block, or the 'mode' parameter contains an invalid/unsupported block cipher mode of operation.
         * @exception SecurityException - Decryption failed.
         */
        static std::vector<std::uint8_t> Decrypt(
            const AesKey& key,
            const std::span<const std::uint8_t> encryptedData,
            const BlockCipherMode mode
        );

        /**
         * Generates a new AES key.
         * 
         * @param keySize The key size (in bits).
         * @returns A newly generated key.
         * @exception std::invalid_argument - The 'keySize' paremeter contains an invalid size for an AES key.
         */
        static AesKey GenerateKey(const std::int32_t keySize);

        /**
         * Generates a new AES key and initialization vector.
         * 
         * @param keySize The key size (in bits).
         * @returns A newly generated key and initialization vector (IV).
         * @exception std::invalid_argument - The 'keySize' paremeter contains an invalid size for an AES key.
         */
        static AesKey GenerateKeyAndIV(const std::int32_t keySize);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_AES_H_