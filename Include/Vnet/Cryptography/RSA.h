/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_RSA_H_
#define _VNETSEC_CRYPTOGRAPHY_RSA_H_

#include <Vnet/Cryptography/RsaKey.h>

#include <span>

namespace Vnet::Cryptography {

    /**
     * Represents the RSA (Rivest–Shamir–Adleman) cryptographic algorithm.
     */
    class VNETSECURITYAPI RSA final {

    public:
        RSA(void) = delete;

        /**
         * Encrypts the input data.
         * 
         * @param key The RSA public/private key.
         * @param data The data to encrypt.
         * @returns The encrypted data.
         * @exception std::invalid_argument - The provided key is not valid.
         * @exception SecurityException - Encryption failed.
         */
        static std::vector<std::uint8_t> Encrypt(const RsaKey& key, const std::span<const std::uint8_t> data);

        /**
         * Decrypts the input data.
         * 
         * @param privateKey The RSA private key.
         * @param data The data to decrypt.
         * @returns The decrypted data.
         * @exception std::invalid_argument - The provided key is not valid, 
         * or a public key is provided instead of a private key.
         * @exception SecurityException - Decryption failed.
         */
        static std::vector<std::uint8_t> Decrypt(const RsaKey& privateKey, const std::span<const std::uint8_t> encryptedData);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_RSA_H_