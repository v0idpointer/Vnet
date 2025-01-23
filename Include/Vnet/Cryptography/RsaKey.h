/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_RSAKEY_H_
#define _VNETSEC_CRYPTOGRAPHY_RSAKEY_H_

#include <Vnet/Cryptography/CryptoKey.h>
#include <Vnet/Cryptography/RsaKeyParameters.h>

namespace Vnet::Cryptography {

    /**
     * Represents an RSA key.
     */
    class VNETSECURITYAPI RsaKey : public CryptoKey {
    
    private:
        RsaKey(NativeCryptoKey_t const key);

    public:
        RsaKey(void);
        RsaKey(RsaKey&& key) noexcept;
        virtual ~RsaKey(void);

        RsaKey& operator= (RsaKey&& key) noexcept;
        bool operator== (const RsaKey& key) const;
        virtual bool operator== (const CryptoKey& key) const override;

        /**
         * Derives the RSA public key from the RSA private key.
         * 
         * @note If this function is called on an RsaKey object containing
         * an RSA public key, a copy of that key is returned.
         * 
         * @returns A newly created RsaKey object containing the matching RSA public key.
         * @exception std::runtime_error - The key is not valid.
         * @exception SecurityException - Thrown if deriving the public key fails.
         */
        RsaKey DerivePublicKey(void) const;

        /**
         * Returns true if the current key is an RSA private key.
         * 
         * @exception std::runtime_error - The key is not valid.
         */
        bool IsPrivateKey(void) const;

        /**
         * Returns true if the current key is an RSA public key.
         * 
         * @exception std::runtime_error - The key is not valid.
         */
        bool IsPublicKey(void) const;

        /**
         * Exports the RSA key parameters.
         * 
         * @returns Key parameters.
         * @exception std::runtime_error - The key is not valid.
         * @exception SecurityException - Key export failed.
         */
        RsaKeyParameters ExportParameters(void) const;

        /**
         * Exports the RSA key in PEM format.
         * 
         * @param password A password used to encrypt the RSA private key.
         * This parameter must be std::nullopt when exporting RSA public keys.
         * @returns A string containing the PEM encoded key.
         * @exception std::runtime_error - The key is not valid.
         * @exception std::invalid_argument - Thrown if a password is provided when exporting a public key.
         * @exception SecurityException - Key export failed.
         */
        std::string ExportPEM(const std::optional<std::string_view> password) const;

        /**
         * Imports an RSA key from the RsaKeyParameters struct.
         * 
         * @param params RSA key parameters.
         * @returns A newly created RsaKey object.
         * @exception SecurityException - Key import failed.
         */
        static RsaKey ImportParameters(const RsaKeyParameters& params);

        /**
         * Imports an RSA key stored in PEM format.
         * 
         * @param pem A string containing an RSA key in PEM format.
         * @param password A password used to decrypt the RSA private key.
         * This parameter must be std::nullopt when importing RSA public keys.
         * @returns A newly created RsaKey object.
         * @exception std::runtime_error - The imported key is not an RSA key.
         * @exception std::invalid_argument - The 'pem' parameter is empty, or 'pem'
         * contains an encrypted RSA private key, but the decryption password is not provided.
         * @exception SecurityException - Key import failed.
         */
        static RsaKey ImportPEM(const std::string_view pem, const std::optional<std::string_view> password);

        /**
         * Generates a new RSA private key.
         * 
         * @param keySize The key size (in bits).
         * @returns A newly generated RSA private key.
         * @exception SecurityException - Key generation failed.
         */
        static RsaKey Generate(const std::int32_t keySize);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_RSAKEY_H_