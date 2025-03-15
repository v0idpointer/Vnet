/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTIFICATE_H_
#define _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTIFICATE_H_

#include <Vnet/DateTime.h>
#include <Vnet/Cryptography/CryptoKey.h>
#include <Vnet/Cryptography/HashAlgorithm.h>

#include <functional>
#include <memory>

struct x509_st;

namespace Vnet::Cryptography::Certificates {

    typedef x509_st* NativeCertificate_t;
    constexpr NativeCertificate_t INVALID_CERTIFICATE_HANDLE = nullptr;

    /**
     * Represents an X.509 certificate.
     */
    class VNETSECURITYAPI Certificate {

    private:
        NativeCertificate_t m_cert;
        std::unique_ptr<CryptoKey> m_privateKey;

    private:
        Certificate(NativeCertificate_t const cert, std::unique_ptr<CryptoKey>&& privateKey) noexcept;

    public:
        Certificate(const Certificate&) = delete;
        Certificate(Certificate&& cert) noexcept;
        virtual ~Certificate(void);

        Certificate& operator= (const Certificate&) = delete;
        Certificate& operator= (Certificate&& cert) noexcept;

        NativeCertificate_t GetNativeCertificateHandle(void) const;

        /**
         * Returns the X.509 certificate's subject name.
         * 
         * @returns A string containing the subject's distinguished name formatted according to RFC 2253.
         * @exception SecurityException
         */
        std::string GetSubjectName(void) const;

        /**
         * Returns the X.509 certificate's issuer name. 
         * 
         * @returns A string containing the certificate issuer's distinguished name formatted according to RFC 2253.
         * @exception SecurityException
         */
        std::string GetIssuerName(void) const;

        /**
         * Returns the datetime when the X.509 certificate becomes valid.
         * 
         * @returns A DateTime.
         * @exception SecurityException
         */
        DateTime GetNotBefore(void) const;

        /**
         * Returns the datetime after which the X.509 certificate becomes invalid.
         * 
         * @returns A DateTime.
         * @exception SecurityException
         */
        DateTime GetNotAfter(void) const;

        /**
         * Returns the version of the X.509 certificate format.
         * 
         * @returns An integer, between 1 and 3.
         */
        std::int32_t GetVersion(void) const;

        /**
         * Returns the X.509 certificate's serial number.
         * 
         * @returns A string containing the serial number in hexadecimal notation.
         * @exception SecurityException
         */
        std::string GetSerialNumber(void) const;

        /**
         * Returns the X.509 certificate's thumbprint.
         * The thumbprint is calculated using the SHA-1 algorithm.
         * 
         * @returns A string containing the thumbprint in hexadecimal notation.
         * @exception SecurityException
         */
        std::string GetThumbprint(void) const;

        /**
         * Returns the X.509 certificate's thumbprint.
         * 
         * @param hashAlg The hash algorithm used to calculate the thumbprint.
         * @returns A string containing the thumbprint in hexadecimal notation.
         * @exception std::invalid_argument - The 'hashAlg' parameter contains an invalid or unsupported hash algorithm
         * @exception SecurityException
         */
        std::string GetThumbprint(const HashAlgorithm hashAlg) const;

        /**
         * Checks if the X.509 certificate has it's corresponding private key.
         * 
         * @returns true if the certificate has it's corresponding private key; otherwise, false.
         */
        bool HasPrivateKey(void) const;

        /**
         * Returns the X.509 certificate's private key.
         * 
         * @returns An optional constant reference to a CryptoKey.
         */
        const std::optional<std::reference_wrapper<const CryptoKey>> GetPrivateKey(void) const;

        /**
         * Returns the X.509 certificate's public key.
         * 
         * @returns A pointer to a CryptoKey.
         * @exception std::runtime_error - The X.509 certificate's public key is of an unknown type.
         * @exception SecurityException
         */
        std::unique_ptr<const CryptoKey> GetPublicKey(void) const;

        /**
         * Exports the X.509 certificate in PEM format.
         * 
         * @returns A string containing the PEM encoded certificate.
         * @exception SecurityException - Certificate export failed.
         */
        std::string ExportPEM(void) const;

        /**
         * Loads an X.509 certificate stored in PEM format.
         * 
         * @param certPem A string containing an X.509 certificate in PEM format.
         * @param privateKey A private key that corresponds to the X.509 certificate being loaded.
         * @returns An X.509 certificate
         * @exception std::invalid_argument - The 'certPem' parameter is empty, or the 'privateKey'
         * parameter contains a symmetric cryptographic key, or 'privateKey' contains an invalid cryptographic key.
         * @exception std::runtime_error - The provided private key is of an unknown type.
         * @exception SecurityException - Certificate import failed, or the provided private key
         * does not correspond to the X.509 certificate.
         */
        static Certificate LoadCertificateFromPEM(const std::string_view certPem, const std::optional<std::reference_wrapper<const CryptoKey>> privateKey);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTIFICATE_H_