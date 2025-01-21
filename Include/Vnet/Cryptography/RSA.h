/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_RSA_H_
#define _VNETSEC_CRYPTOGRAPHY_RSA_H_

#include <Vnet/Cryptography/RsaKey.h>
#include <Vnet/Cryptography/RsaEncryptionPadding.h>

#include <unordered_map>
#include <tuple>
#include <span>

struct evp_md_st;

namespace Vnet::Cryptography {

    /**
     * Represents the RSA (Rivest–Shamir–Adleman) cryptographic algorithm.
     */
    class VNETSECURITYAPI RSA final {

    private:
        static const std::unordered_map<RsaEncryptionPadding, std::tuple<std::int32_t, const evp_md_st* (*)(void), const evp_md_st* (*)(void)>> s_paddings;

    public:
        RSA(void) = delete;

        /**
         * Encrypts the input data.
         * 
         * @param key The RSA public/private key.
         * @param data The data to encrypt.
         * @param padding A value from the RsaEncryptionPadding enum. The exact value should later be used to decrypt the data.
         * @returns The encrypted data.
         * @exception std::invalid_argument - The provided key is not valid.
         * @exception SecurityException - Encryption failed.
         */
        static std::vector<std::uint8_t> Encrypt(const RsaKey& key, const std::span<const std::uint8_t> data, const RsaEncryptionPadding padding);

        /**
         * Decrypts the input data.
         * 
         * @param privateKey The RSA private key.
         * @param data The data to decrypt.
         * @param padding The padding used to encrypt the data.
         * @returns The decrypted data.
         * @exception std::invalid_argument - The provided key is not valid, 
         * or a public key is provided instead of a private key.
         * @exception SecurityException - Decryption failed.
         */
        static std::vector<std::uint8_t> Decrypt(const RsaKey& privateKey, const std::span<const std::uint8_t> encryptedData, const RsaEncryptionPadding padding);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_RSA_H_