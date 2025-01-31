/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTIFICATESTORE_H_
#define _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTIFICATESTORE_H_

#include <Vnet/Cryptography/Certificates/Certificate.h>

#include <vector>

namespace Vnet::Cryptography::Certificates {

    typedef void* NativeCertStore_t;
    constexpr NativeCertStore_t INVALID_CERT_STORE_HANDLE = nullptr;

    /**
     * Represents an X.509 certificate store.
     */
    class VNETSECURITYAPI CertificateStore {

    private:
        NativeCertStore_t m_certStore;

    private:
        CertificateStore(NativeCertStore_t const certStore);

    public:
        CertificateStore(void);
        CertificateStore(const CertificateStore&) = delete;
        CertificateStore(CertificateStore&& certStore) noexcept;
        virtual ~CertificateStore(void);

        CertificateStore& operator= (const CertificateStore&) = delete;
        CertificateStore& operator= (CertificateStore&& certStore) noexcept;

        NativeCertStore_t GetNativeCertStoreHandle(void) const;

        /**
         * Returns all X.509 certificates from the certificate store.
         * 
         * @returns An std::vector containing heap allocated certificates.
         * @exception std::runtime_error - The certificate store is not valid.
         * @exception SecurityException
         */
        std::vector<std::shared_ptr<Certificate>> GetCertificates(void) const;

        /**
         * Adds an X.509 certificate to the certificate store.
         * 
         * @param cert An X.509 certificate.
         * @exception std::runtime_error - The certificate store is not valid.
         * @exception std::invalid_argument - The 'cert' parameter contains an invalid certificate,
         * or the specified certificate is already in the certificate store.
         * @exception SecurityException
         */
        void Add(const Certificate& cert);

        /**
         * Removes an X.509 certificate from the certificate store.
         * 
         * @param cert An X.509 certificate.
         * @exception std::runtime_error - The certificate store is not valid.
         * @exception std::invalid_argument - The 'cert' parameter contains an invalid certificate,
         * or the specified certificate does not exist in the certificate store.
         * @exception SecurityException
         */
        void Remove(const Certificate& cert);

        /**
         * TEST FUNCTION.
         * 
         * Replace this later in development with a general OpenStore
         * that accepts store name (either as an enum or as a wstring)
         * and store location (current user / local machine).
         * 
         * @returns A newly created CertificateStore object.
         * @exception std::runtime_error
         * @exception SecurityException
         */
        static CertificateStore OpenPersonalCertStore(void);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTIFICATESTORE_H_