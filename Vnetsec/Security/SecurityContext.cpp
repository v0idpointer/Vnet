/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Security/SecurityContext.h>
#include <Vnet/Security/SecurityException.h>

#include <Vnet/Cryptography/KeyUtils.h>
#include <Vnet/Cryptography/CryptoKey.h>
#include <Vnet/Cryptography/Certificates/Certificate.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace Vnet::Security;
using namespace Vnet::Cryptography;
using namespace Vnet::Cryptography::Certificates;

SecurityContext::SecurityContext(const ApplicationType appType, const SecurityProtocol protocol) : m_ctx(INVALID_SECURITY_CONTEXT_HANDLE) {

    this->m_applicationType = appType;
    this->m_securityProtocol = protocol;

    const SSL_METHOD* method = nullptr;
    if (appType == ApplicationType::CLIENT) method = SSLv23_client_method();
    else method = SSLv23_server_method();

    this->m_ctx = SSL_CTX_new(method);
    if (this->m_ctx == nullptr) throw SecurityException(ERR_get_error());

    if (protocol != SecurityProtocol::UNSPECIFIED) { 

        std::uint64_t options = (SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3);
        if (static_cast<std::int32_t>(protocol & SecurityProtocol::SSL_2_0)) options &= ~SSL_OP_NO_SSLv2;
        if (static_cast<std::int32_t>(protocol & SecurityProtocol::SSL_3_0)) options &= ~SSL_OP_NO_SSLv3;
        if (static_cast<std::int32_t>(protocol & SecurityProtocol::TLS_1_0)) options &= ~SSL_OP_NO_TLSv1;
        if (static_cast<std::int32_t>(protocol & SecurityProtocol::TLS_1_1)) options &= ~SSL_OP_NO_TLSv1_1;
        if (static_cast<std::int32_t>(protocol & SecurityProtocol::TLS_1_2)) options &= ~SSL_OP_NO_TLSv1_2;
        if (static_cast<std::int32_t>(protocol & SecurityProtocol::TLS_1_3)) options &= ~SSL_OP_NO_TLSv1_3;

        SSL_CTX_set_options(this->m_ctx, options);

    }

}

SecurityContext::SecurityContext(SecurityContext&& ctx) noexcept : m_ctx(INVALID_SECURITY_CONTEXT_HANDLE) {
    this->operator= (std::move(ctx));
}

SecurityContext::~SecurityContext() {

    if (this->m_ctx != INVALID_SECURITY_CONTEXT_HANDLE) {
        SSL_CTX_free(this->m_ctx);
        this->m_ctx = INVALID_SECURITY_CONTEXT_HANDLE;
    }

}

SecurityContext& SecurityContext::operator= (SecurityContext&& ctx) noexcept {

    if (this != &ctx) {

        if (this->m_ctx != INVALID_SECURITY_CONTEXT_HANDLE) {
            SSL_CTX_free(this->m_ctx);
            this->m_ctx = INVALID_SECURITY_CONTEXT_HANDLE;
        }

        this->m_ctx = ctx.m_ctx;
        ctx.m_ctx = INVALID_SECURITY_CONTEXT_HANDLE;

        this->m_applicationType = ctx.m_applicationType;
        this->m_securityProtocol = ctx.m_securityProtocol;
        this->m_cert = std::move(ctx.m_cert);
        this->m_privateKey = std::move(ctx.m_privateKey);

    }

    return static_cast<SecurityContext&>(*this);
}

NativeSecurityContext_t SecurityContext::GetNativeSecurityContextHandle() const {
    return this->m_ctx;
}

Vnet::Security::ApplicationType SecurityContext::GetApplicationType() const {
    return this->m_applicationType;
}

SecurityProtocol SecurityContext::GetSecurityProtocol() const {
    return this->m_securityProtocol;
}

const std::optional<std::reference_wrapper<const Certificate>> SecurityContext::GetCertificate() const {

    if (this->m_ctx == INVALID_SECURITY_CONTEXT_HANDLE)
        throw std::runtime_error("Invalid security context.");

    if (this->m_cert) return std::cref(*this->m_cert);
    else return std::nullopt;
}

const std::optional<std::reference_wrapper<const CryptoKey>> SecurityContext::GetPrivateKey() const {

    if (this->m_ctx == INVALID_SECURITY_CONTEXT_HANDLE)
        throw std::runtime_error("Invalid security context.");

    if (this->m_privateKey) return std::cref(*this->m_privateKey);
    else return std::nullopt;
}

static inline std::unique_ptr<Certificate> DuplicateCertificate(const Certificate& cert) {

    std::optional<std::reference_wrapper<const CryptoKey>> privateKey = std::nullopt;
    if (cert.HasPrivateKey()) privateKey = std::cref(*cert.GetPrivateKey());

    return std::make_unique<Certificate>(Certificate::LoadCertificateFromPEM(cert.ExportPEM(), privateKey));
}

void SecurityContext::SetCertificate(const std::optional<std::reference_wrapper<const Certificate>> cert) {

    if (this->m_ctx == INVALID_SECURITY_CONTEXT_HANDLE)
        throw std::runtime_error("Invalid security context.");

    if (!cert.has_value()) throw std::invalid_argument("'cert': std::nullopt");
    else {

        if (cert->get().GetNativeCertificateHandle() == INVALID_CERTIFICATE_HANDLE)
            throw std::invalid_argument("'cert': Invalid certificate.");

        this->m_cert = DuplicateCertificate(cert->get());
        if (this->m_cert->HasPrivateKey())
            this->SetPrivateKey(this->m_cert->GetPrivateKey());

    }

    NativeCertificate_t certHandle = (this->m_cert ? this->m_cert->GetNativeCertificateHandle() : nullptr);
    if (SSL_CTX_use_certificate(this->m_ctx, certHandle) != 1)
        throw SecurityException(ERR_get_error());

}

void SecurityContext::SetPrivateKey(const std::optional<std::reference_wrapper<const CryptoKey>> privateKey) {

    if (this->m_ctx == INVALID_SECURITY_CONTEXT_HANDLE)
        throw std::runtime_error("Invalid security context.");

    if (!privateKey.has_value()) throw std::invalid_argument("'privateKey': std::nullopt"); // OpenSSL for some fucking reason doesn't allow
    else {                                                                                  // you to remove an EVP_PKEY from an SSL_CTX ???

        if (privateKey->get().GetNativeKeyHandle() == INVALID_KEY_HANDLE)
            throw std::invalid_argument("'privateKey': Invalid key.");

        this->m_privateKey = KeyUtils::DuplicateKey(privateKey->get());

    }

    NativeCryptoKey_t keyHandle = (this->m_privateKey ? this->m_privateKey->GetNativeKeyHandle() : nullptr);
    if (SSL_CTX_use_PrivateKey(this->m_ctx, keyHandle) != 1)
        throw SecurityException(ERR_get_error());

}