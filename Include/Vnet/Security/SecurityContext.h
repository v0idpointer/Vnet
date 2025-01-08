/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_SECURITY_SECURITYCONTEXT_H_
#define _VNETSEC_SECURITY_SECURITYCONTEXT_H_

#include <Vnet/Security/ApplicationType.h>
#include <Vnet/Security/SecurityProtocol.h>

struct ssl_ctx_st;

namespace Vnet::Security {

    typedef ssl_ctx_st* NativeSecurityContext_t;
    constexpr NativeSecurityContext_t INVALID_SECURITY_CONTEXT_HANDLE = nullptr;

    /**
     * 
     */
    class VNETSECURITYAPI SecurityContext {

    private:
        NativeSecurityContext_t m_ctx;

    public:
        SecurityContext(void);
        SecurityContext(const ApplicationType appType, const SecurityProtocol protocol);
        SecurityContext(const SecurityContext&) = delete;
        SecurityContext(SecurityContext&& ctx) noexcept;
        virtual ~SecurityContext(void);

        SecurityContext& operator= (const SecurityContext&) = delete;
        SecurityContext& operator= (SecurityContext&& ctx) noexcept;

        NativeSecurityContext_t GetNativeSecurityContextHandle(void) const;

    };

}

#endif // _VNETSEC_SECURITY_SECURITYCONTEXT_H_