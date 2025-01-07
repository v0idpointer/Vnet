/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTIFICATE_H_
#define _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTIFICATE_H_

#include <Vnet/DateTime.h>
#include <Vnet/Cryptography/CryptoKey.h>

#include <functional>

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
        std::optional<CryptoKey> m_privateKey;

    private:
        Certificate(NativeCertificate_t const cert, std::optional<CryptoKey>&& privateKey) noexcept;

    public:
        Certificate(void);
        Certificate(const Certificate&) = delete;
        Certificate(Certificate&& cert) noexcept;
        virtual ~Certificate(void);

        Certificate& operator= (const Certificate&) = delete;
        Certificate& operator= (Certificate&& cert) noexcept;

        NativeCertificate_t GetNativeCertificateHandle(void) const;

        /**
         * Returns the subject's distinguished name formatted according to RFC 2253.
         * 
         * @exception std::runtime_error - The certificate is not valid.
         * @exception SecurityException
         */
        std::string GetSubjectName(void) const;

        /**
         * Returns the certificate issuer's distinguished name formatted according to RFC 2253.
         * 
         * @exception std::runtime_error - The certificate is not valid.
         * @exception SecurityException
         */
        std::string GetIssuerName(void) const;

        /**
         * Returns the datetime when the X.509 certificate becomes valid.
         * 
         * @exception std::runtime_error - The certificate is not valid.
         * @exception SecurityException
         */
        DateTime GetNotBefore(void) const;

        /**
         * Returns the datetime after which the X.509 certificate becomes invalid.
         * 
         * @exception std::runtime_error - The certificate is not valid.
         * @exception SecurityException
         */
        DateTime GetNotAfter(void) const;

        /**
         * Returns the version of the X.509 certificate format.
         * 
         * @exception std::runtime_error - The certificate is not valid.
         */
        std::int32_t GetVersion(void) const;

        /**
         * Returns the X.509 certificate's serial number.
         * 
         * @exception std::runtime_error - The certificate is not valid.
         * @exception SecurityException
         */
        std::string GetSerialNumber(void) const;

        /**
         * Returns the X.509 certificate's thumbprint.
         * The thumbprint is calculated using the SHA-1 algorithm.
         * 
         * @exception std::runtime_error - The certificate is not valid.
         * @exception SecurityException
         */
        std::string GetThumbprint(void) const;

        /**
         * Returns true if the X.509 certificate has it's corresponding private key.
         * 
         * @exception std::runtime_error - The certificate is not valid.
         */
        bool HasPrivateKey(void) const;

        /**
         * Returns the X.509 certificate's private key.
         * 
         * @exception std::runtime_error - The certificate is not valid.
         */
        const std::optional<CryptoKey>& GetPrivateKey(void) const;

        /**
         * Returns the X.509 certificate's public key.
         * 
         * @exception std::runtime_error - The certificate is not valid, or the X.509 
         * certificate's public key is of an unknown type.
         * @exception SecurityException
         */
        CryptoKey GetPublicKey(void) const;

        /**
         * Exports the X.509 certificate in PEM format.
         * 
         * @returns A string containing the PEM encoded certificate.
         * @exception std::runtime_error - The certificate is not valid.
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
         * parameter contains an invalid key.
         * @exception std::runtime_error - The provided private key is of an unknown type.
         * @exception SecurityException - Certificate import failed, or the provided private key
         * does not correspond to the X.509 certificate.
         */
        static Certificate LoadCertificateFromPEM(const std::string_view certPem, const std::optional<std::reference_wrapper<CryptoKey>> privateKey);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTIFICATE_H_