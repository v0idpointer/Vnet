/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Security/SecurityContext.h>
#include <Vnet/Security/SecurityException.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace Vnet::Security;

SecurityContext::SecurityContext() : m_ctx(INVALID_SECURITY_CONTEXT_HANDLE) { }

SecurityContext::SecurityContext(const ApplicationType appType, const SecurityProtocol protocol) : m_ctx(INVALID_SECURITY_CONTEXT_HANDLE) {

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

    }

    return static_cast<SecurityContext&>(*this);
}

NativeSecurityContext_t SecurityContext::GetNativeSecurityContextHandle() const {
    return this->m_ctx;
}