/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_SECURITY_SECURITYCONTEXT_H_
#define _VNETSEC_SECURITY_SECURITYCONTEXT_H_

#include <Vnet/Security/ApplicationType.h>
#include <Vnet/Security/SecurityProtocol.h>

#include <memory>
#include <optional>
#include <functional>

struct ssl_ctx_st;

namespace Vnet::Cryptography {
    class CryptoKey;
}

namespace Vnet::Cryptography::Certificates {
    class Certificate;
}

namespace Vnet::Security {

    typedef ssl_ctx_st* NativeSecurityContext_t;
    constexpr NativeSecurityContext_t INVALID_SECURITY_CONTEXT_HANDLE = nullptr;

    /**
     * Stores configuration used for the creation of secure connections.
     */
    class VNETSECURITYAPI SecurityContext {

    private:
        NativeSecurityContext_t m_ctx;
        ApplicationType m_applicationType;
        SecurityProtocol m_securityProtocol;
        std::unique_ptr<Vnet::Cryptography::Certificates::Certificate> m_cert;
        std::unique_ptr<Vnet::Cryptography::CryptoKey> m_privateKey;

    public:

        /**
         * Constructs a new SecurityContext object.
         * 
         * @param appType ApplicationType::CLIENT or ApplicationType::SERVER.
         * @param protocol One or more values, bitwise OR-ed together, from the SecurityProtocol enum.
         * If SecurityProtocol::UNSPECIFIED is provided, the default protocols will be selected.
         * @exception std::invalid_argument - The 'appType' parameter contains an invalid
         * application type, or 'protocol' contains an invalid and/or unsupported security protocol.
         * @exception SecurityException
         */
        SecurityContext(const ApplicationType appType, const SecurityProtocol protocol);

        SecurityContext(const SecurityContext&) = delete;
        SecurityContext(SecurityContext&& ctx) noexcept;
        virtual ~SecurityContext(void);

        SecurityContext& operator= (const SecurityContext&) = delete;
        SecurityContext& operator= (SecurityContext&& ctx) noexcept;

        /**
         * Returns the native security context handle.
         * 
         * @note DO NOT MANUALLY FREE THIS HANDLE!
         * 
         * This handle is managed by the current SecurityContext object,
         * and manually freeing it will cause undefined behavior that can break Vnetsec.
         * 
         * @returns A NativeSecurityContext_t.
         */
        NativeSecurityContext_t GetNativeSecurityContextHandle(void) const;

        /**
         * Returns the type of application using this security context.
         * 
         * @returns A value from the ApplicationType enum.
         */
        ApplicationType GetApplicationType(void) const;

        /**
         * Returns the selected security protocol(s).
         * 
         * @returns One or more values, bitwise OR-ed together, from the SecurityProtocol enum.
         */
        SecurityProtocol GetSecurityProtocol(void) const;

        /**
         * Returns the security context's X.509 certificate.
         * 
         * @returns An optional X.509 certificate.
         */
        const std::optional<std::reference_wrapper<const Cryptography::Certificates::Certificate>> GetCertificate(void) const;

        /**
         * Returns the security context's private key.
         * 
         * @returns An optional cryptographic key.
         */
        const std::optional<std::reference_wrapper<const Cryptography::CryptoKey>> GetPrivateKey(void) const;

        /**
         * Sets an X.509 certificate to be used with the security context.
         * 
         * If the provided X.509 certificate has its corresponding private key,
         * this function will also set the private key to be used with
         * the current security context.
         * 
         * @param cert An X.509 certificate.
         * @exception std::invalid_argument - The 'cert' parameter is std::nullopt,
         * or the certificate's private key is of an unknown type.
         * @exception SecurityException
         */
        void SetCertificate(const std::optional<std::reference_wrapper<const Cryptography::Certificates::Certificate>> cert);

        /**
         * Sets a private key to be used with the security context.
         * 
         * @param privateKey A private key.
         * @exception std::invalid_argument - The 'privateKey' parameter is std::nullopt,
         * or 'privateKey' contains a symmetric key, or 'privateKey' contains an invalid key,
         * or 'privateKey' is of an unknown type.
         * @exception SecurityException
         */
        void SetPrivateKey(const std::optional<std::reference_wrapper<const Cryptography::CryptoKey>> privateKey);

    };

}

#endif // _VNETSEC_SECURITY_SECURITYCONTEXT_H_