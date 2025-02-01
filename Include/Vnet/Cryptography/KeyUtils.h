/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_KEYUTILS_H_
#define _VNETSEC_CRYPTOGRAPHY_KEYUTILS_H_

#include <Vnet/Cryptography/CryptoKey.h>

#include <memory>

namespace Vnet::Cryptography {

    /**
     * Contains helper functions related to cryptographic keys.
     */
    class VNETSECURITYAPI KeyUtils final {

    public:
        KeyUtils(void) = delete;

        /**
         * Creates a duplicate of a given key.
         * 
         * @param key A cryptographic key to duplicate.
         * @returns An std::unique_ptr to the duplicated key.
         * @exception std::runtime_error - The provided key is of an unknown type.
         * @exception SecurityException - Key duplication failed.
         */
        static std::unique_ptr<CryptoKey> DuplicateKey(const CryptoKey& key);

        /**
         * Imports a cryptographic key stored in PEM format.
         * 
         * @param pem A string containing a cryptographic key in PEM format.
         * @param password A password used to decrypt the private key.
         * This parameter must be std::nullopt when importing public keys.
         * @exception std::runtime_error - The 'pem' parameter contains a key of an unknown type.
         * @exception std::invalid_argument - The 'pem' parameter is empty, or 'pem'
         * contains an encrypted private key, but the decryption password is not provided.
         * @exception SecurityException - Key import failed.
         */
        static std::unique_ptr<CryptoKey> ImportPEM(const std::string_view pem, const std::optional<std::string_view> password);

        /**
         * Returns true if the provided key is a symmetric cryptographic key.
         */
        static bool IsSymmetricKey(const CryptoKey& key) noexcept;

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_KEYUTILS_H_