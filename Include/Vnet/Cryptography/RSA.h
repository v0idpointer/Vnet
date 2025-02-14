/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_RSA_H_
#define _VNETSEC_CRYPTOGRAPHY_RSA_H_

#include <Vnet/Cryptography/RsaKey.h>
#include <Vnet/Cryptography/RsaEncryptionPadding.h>
#include <Vnet/Cryptography/RsaSignaturePadding.h>
#include <Vnet/Cryptography/HashAlgorithm.h>

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
        static const std::unordered_map<RsaSignaturePadding, std::int32_t> s_signPaddings;

    public:
        RSA(void) = delete;

        /**
         * Encrypts the input data.
         * 
         * @param key The RSA public/private key.
         * @param data The data to encrypt.
         * @param padding A value from the RsaEncryptionPadding enum. The exact value should later be used to decrypt the data.
         * @returns The encrypted data.
         * @exception std::invalid_argument - The 'padding' parameter contains an invalid encryption padding mode.
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
         * @exception std::invalid_argument - A public key is provided instead of a private key, 
         * or the 'padding' parameter contains an invalid encryption padding mode.
         * @exception SecurityException - Decryption failed.
         */
        static std::vector<std::uint8_t> Decrypt(const RsaKey& privateKey, const std::span<const std::uint8_t> encryptedData, const RsaEncryptionPadding padding);

        /**
         * Signs the input data.
         * 
         * @param privateKey The RSA private key.
         * @param data The data to sign.
         * @param hashAlg The hash algorithm to create a hash of the input data.
         * @param padding A value from the RsaSignaturePadding enum.
         * @returns The signed data.
         * @exception std::invalid_argument - The 'hashAlg' parameter contains an invalid hash algorithm,
         * or a public key is provided instead of a private key, or the 'padding' parameter contains an invalid signature padding mode.
         * @exception SecurityException - Hash function failed, or signing failed.
         */
        static std::vector<std::uint8_t> Sign(
            const RsaKey& privateKey, 
            const std::span<const std::uint8_t> data, 
            const HashAlgorithm hashAlg, 
            const RsaSignaturePadding padding
        );

        /**
         * Signs the input hashed data.
         * 
         * @param privateKey The RSA private key.
         * @param hashedData The hash value of the data to sign.
         * @param hashAlg The hash algorithm used to hash the data.
         * @param padding A value from the RsaSignaturePadding enum.
         * @returns The signed data.
         * @exception std::invalid_argument - The 'hashAlg' parameter contains an invalid hash algorithm,
         * or a public key is provided instead of a private key, or the 'padding' parameter contains an invalid signature padding mode.
         * @exception SecurityException - Signing failed.
         */
        static std::vector<std::uint8_t> SignHashed(
            const RsaKey& privateKey, 
            const std::span<const std::uint8_t> hashedData, 
            const HashAlgorithm hashAlg, 
            const RsaSignaturePadding padding
        );

        /**
         * Verifies a signature.
         * 
         * @param key The RSA public/private key.
         * @param data The signed data.
         * @param signature The signature data.
         * @param hashAlg The hash algorithm to create a hash of the signed data.
         * @param padding The padding used to sign the data.
         * @returns true if the signature is valid; otherwise, false.
         * @exception std::invalid_argument - The 'hashAlg' parameter contains an invalid hash algorithm,
         * or the 'padding' parameter contains an invalid signature padding mode.
         * @exception SecurityException - Hash function failed, or verification failed.
         */
        static bool Verify(
            const RsaKey& key, 
            const std::span<const std::uint8_t> data, 
            const std::span<const std::uint8_t> signature, 
            const HashAlgorithm hashAlg, 
            const RsaSignaturePadding padding
        );

        /**
         * Verifies a signature.
         * 
         * @param key The RSA public/private key.
         * @param hashedData The hash value of the signed data.
         * @param signature The signature data.
         * @param hashAlg The hash algorithm used to hash the signed data.
         * @param padding The padding used to sign the data.
         * @returns true if the signature is valid; otherwise, false.
         * @exception std::invalid_argument - The 'hashAlg' parameter contains an invalid hash algorithm,
         * or the 'padding' parameter contains an invalid signature padding mode.
         * @exception SecurityException - Verification failed.
         */
        static bool VerifyHashed(
            const RsaKey& key, 
            const std::span<const std::uint8_t> hashedData, 
            const std::span<const std::uint8_t> signature, 
            const HashAlgorithm hashAlg, 
            const RsaSignaturePadding padding
        );

        /**
         * Generates a new RSA key pair.
         * 
         * @param keySize The key size (in bits).
         * @returns A newly generated key pair.
         * @exception SecurityException - Key generation failed.
         */
        static RsaKey GenerateKeyPair(const std::int32_t keySize);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_RSA_H_