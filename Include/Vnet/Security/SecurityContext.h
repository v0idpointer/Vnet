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
        std::unique_ptr<Vnet::Cryptography::Certificates::Certificate> m_cert;
        std::unique_ptr<Vnet::Cryptography::CryptoKey> m_privateKey;

    public:

        /**
         * Constructs a new SecurityContext object.
         * 
         * The newly created security context will be invalid.
         */
        SecurityContext(void);

        /**
         * Constructs a new SecurityContext object.
         * 
         * @param appType ApplicationType::CLIENT or ApplicationType::SERVER.
         * @param protocol One or more values, bitwise OR-ed together, from the SecurityProtocol enum.
         * If SecurityProtocol::UNSPECIFIED is provided, the default protocols will be selected.
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
         * Returns the security context's X.509 certificate.
         * 
         * @returns An optional X.509 certificate.
         * @exception std::runtime_error - The security context is not valid.
         */
        const std::optional<std::reference_wrapper<const Cryptography::Certificates::Certificate>> GetCertificate(void) const;

        /**
         * Returns the security context's private key.
         * 
         * @returns An optional cryptographic key.
         * @exception std::runtime_error - The security context is not valid.
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
         * @exception std::runtime_error - The security context is not valid, or the certificate's private key
         * is of an unknown type.
         * @exception std::invalid_argument - The 'cert' parameter contains an invalid certificate,
         * or the provided certificate contains an invalid private key, or 'cert' is std::nullopt.
         * @exception SecurityException
         */
        void SetCertificate(const std::optional<std::reference_wrapper<const Cryptography::Certificates::Certificate>> cert);

        /**
         * Sets a private key to be used with the security context.
         * 
         * @param privateKey A private key.
         * @exception std::runtime_error - The security context is not valid, or the provided
         * key is of an unknown type.
         * @exception std::invalid_argument - The 'privateKey' parameter contains an invalid key,
         * or 'privateKey' is std::nullopt.
         * @exception SecurityException
         */
        void SetPrivateKey(const std::optional<std::reference_wrapper<const Cryptography::CryptoKey>> privateKey);

    };

}

#endif // _VNETSEC_SECURITY_SECURITYCONTEXT_H_