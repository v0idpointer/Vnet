/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Security/SecurityContext.h>
#include <Vnet/Security/SecurityException.h>

#include <Vnet/Cryptography/KeyUtils.h>
#include <Vnet/Cryptography/CryptoKey.h>
#include <Vnet/Cryptography/Certificates/Certificate.h>

#include <Vnet/InvalidObjectStateException.h>
#include <Vnet/Util/String.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace Vnet::Security;
using namespace Vnet::Cryptography;
using namespace Vnet::Cryptography::Certificates;

SecurityContext::SecurityContext(const ApplicationType appType, const SecurityProtocol protocol) : m_ctx(INVALID_SECURITY_CONTEXT_HANDLE) {

    if ((appType != ApplicationType::CLIENT) && (appType != ApplicationType::SERVER))
        throw std::invalid_argument("'appType': Invalid application type.");

    if (static_cast<std::uint32_t>(protocol) >= 64)
        throw std::invalid_argument("'protocol': Invalid and/or unsupported security protocol.");

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

    this->m_sniEnabled = false;
    this->m_sni = { };

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
        this->m_sniEnabled = ctx.m_sniEnabled;
        this->m_sni = std::move(ctx.m_sni);

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
    if (this->m_cert) return std::cref(*this->m_cert);
    else return std::nullopt;
}

const std::optional<std::reference_wrapper<const Certificate>> SecurityContext::GetCertificate(const std::string_view serverName) const {
    
    if (this->m_applicationType != ApplicationType::SERVER)
        throw InvalidObjectStateException("The current SecurityContext object is not a server security context.");

    if (serverName.empty())
        throw std::invalid_argument("'serverName': Empty string.");

    std::string name = ToLowercase(serverName);
    if (!this->m_sni.contains(name)) return std::nullopt;

    const auto& [certificate, _] = this->m_sni.at(name);

    if (certificate) return std::cref(*certificate);
    else return std::nullopt;
}

const std::optional<std::reference_wrapper<const CryptoKey>> SecurityContext::GetPrivateKey() const {
    if (this->m_privateKey) return std::cref(*this->m_privateKey);
    else return std::nullopt;
}

const std::optional<std::reference_wrapper<const CryptoKey>> SecurityContext::GetPrivateKey(const std::string_view serverName) const {

    if (this->m_applicationType != ApplicationType::SERVER)
        throw InvalidObjectStateException("The current SecurityContext object is not a server security context.");

    if (serverName.empty())
        throw std::invalid_argument("'serverName': Empty string.");

    std::string name = ToLowercase(serverName);
    if (!this->m_sni.contains(name)) return std::nullopt;

    const auto& [_, privateKey] = this->m_sni.at(name);

    if (privateKey) return std::cref(*privateKey);
    else return std::nullopt;
}

bool SecurityContext::IsServerNameIndicationEnabled() const {
    return this->m_sniEnabled;
}

static inline std::unique_ptr<Certificate> DuplicateCertificate(const Certificate& cert) {

    std::optional<std::reference_wrapper<const CryptoKey>> privateKey = std::nullopt;
    if (cert.HasPrivateKey()) privateKey = std::cref(*cert.GetPrivateKey());

    return std::make_unique<Certificate>(Certificate::LoadCertificateFromPEM(cert.ExportPEM(), privateKey));
}

void SecurityContext::SetCertificate(const std::optional<std::reference_wrapper<const Certificate>> cert) {

    if (!cert.has_value()) throw std::invalid_argument("'cert': std::nullopt");
    else {

        this->m_cert = DuplicateCertificate(cert->get());
        if (this->m_cert->HasPrivateKey())
            this->SetPrivateKey(this->m_cert->GetPrivateKey());

    }

    NativeCertificate_t certHandle = (this->m_cert ? this->m_cert->GetNativeCertificateHandle() : nullptr);
    if (SSL_CTX_use_certificate(this->m_ctx, certHandle) != 1)
        throw SecurityException(ERR_get_error());

}

void SecurityContext::SetCertificate(const std::string_view serverName, const std::optional<std::reference_wrapper<const Certificate>> cert) {

    if (this->m_applicationType != ApplicationType::SERVER)
        throw InvalidObjectStateException("The current SecurityContext object is not a server security context.");

    if (serverName.empty())
        throw std::invalid_argument("'serverName': Empty string.");

    std::string name = ToLowercase(serverName);
    if (!this->m_sni.contains(name))
        this->m_sni.insert({ name, { nullptr, nullptr } });

    auto& [certificate, privateKey] = this->m_sni.at(name);

    if (!cert.has_value()) certificate = nullptr;
    else {

        certificate = DuplicateCertificate(cert->get());
        if (certificate->HasPrivateKey())
            this->SetPrivateKey(serverName, certificate->GetPrivateKey());

    }

    if ((certificate == nullptr) && (privateKey == nullptr))
        this->m_sni.erase(name);
    
}

void SecurityContext::SetPrivateKey(const std::optional<std::reference_wrapper<const CryptoKey>> privateKey) {

    if (!privateKey.has_value()) throw std::invalid_argument("'privateKey': std::nullopt"); // OpenSSL for some fucking reason doesn't allow
    else {                                                                                  // you to remove an EVP_PKEY from an SSL_CTX ???

        if (KeyUtils::IsSymmetricKey(privateKey->get()))
            throw std::invalid_argument("'privateKey': Symmetric key.");

        if (privateKey->get().GetNativeKeyHandle() == INVALID_KEY_HANDLE)
            throw std::invalid_argument("'privateKey': Invalid key.");

        try { this->m_privateKey = KeyUtils::DuplicateKey(privateKey->get()); }
        catch (const std::invalid_argument& ex) {
            using namespace std::string_literals;
            throw std::invalid_argument("'privateKey': "s + ex.what());
        }

    }

    NativeCryptoKey_t keyHandle = (this->m_privateKey ? this->m_privateKey->GetNativeKeyHandle() : nullptr);
    if (SSL_CTX_use_PrivateKey(this->m_ctx, keyHandle) != 1)
        throw SecurityException(ERR_get_error());

}

void SecurityContext::SetPrivateKey(const std::string_view serverName, const std::optional<std::reference_wrapper<const CryptoKey>> privateKey) {
    
    if (this->m_applicationType != ApplicationType::SERVER)
        throw InvalidObjectStateException("The current SecurityContext object is not a server security context.");

    if (serverName.empty())
        throw std::invalid_argument("'serverName': Empty string.");

    std::string name = ToLowercase(serverName);
    if (!this->m_sni.contains(name))
        this->m_sni.insert({ name, { nullptr, nullptr } });

    auto& [cert, key] = this->m_sni.at(name);

    if (!privateKey.has_value()) key = nullptr;
    else {

        if (KeyUtils::IsSymmetricKey(privateKey->get()))
            throw std::invalid_argument("'privateKey': Symmetric key.");

        if (privateKey->get().GetNativeKeyHandle() == INVALID_KEY_HANDLE)
            throw std::invalid_argument("'privateKey': Invalid key.");

        try { key = KeyUtils::DuplicateKey(privateKey->get()); }
        catch (const std::invalid_argument& ex) {
            using namespace std::string_literals;
            throw std::invalid_argument("'privateKey': "s + ex.what());
        }

    }

    if ((cert == nullptr) && (key == nullptr))
        this->m_sni.erase(name);

}

void SecurityContext::SetServerNameIndicationEnabled(const bool enabled) {
    
    if (this->m_applicationType != ApplicationType::SERVER)
        throw InvalidObjectStateException("The current SecurityContext object is not a server security context.");

    if (!enabled) {

        SSL_CTX_set_tlsext_servername_callback(this->m_ctx, nullptr);
        SSL_CTX_set_tlsext_servername_arg(this->m_ctx, nullptr);
        this->m_sniEnabled = false;

        return;
    }

    int (*callback) (SSL*, int*, void*) = [] (SSL* ssl, int*, void* arg) -> int {
        
        const SecurityContext* pSecCtx = reinterpret_cast<const SecurityContext*>(arg);
        const char* szServerName = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

        if ((szServerName == nullptr) || *szServerName == '\0')
            return SSL_TLSEXT_ERR_ALERT_FATAL;

        std::string serverName = { szServerName };
        ToLowercase(serverName.begin(), serverName.end());

        if (pSecCtx->m_sni.contains(serverName)) {

            const auto [certificate, privateKey] = pSecCtx->m_sni.at(serverName);
            
            if ((certificate == nullptr) || (privateKey == nullptr)) 
                return SSL_TLSEXT_ERR_ALERT_FATAL;

            if (SSL_use_certificate(ssl, certificate->GetNativeCertificateHandle()) != 1)
                return SSL_TLSEXT_ERR_ALERT_FATAL;

            if (SSL_use_PrivateKey(ssl, privateKey->GetNativeKeyHandle()) != 1)
                return SSL_TLSEXT_ERR_ALERT_FATAL;

            return SSL_TLSEXT_ERR_OK;
        }

        return SSL_TLSEXT_ERR_ALERT_FATAL;
    };

    SSL_CTX_set_tlsext_servername_callback(this->m_ctx, callback);
    SSL_CTX_set_tlsext_servername_arg(this->m_ctx, this);
    this->m_sniEnabled = true;

}