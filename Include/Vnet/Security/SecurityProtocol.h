/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_SECURITY_SECURITYPROTOCOL_H_
#define _VNETSEC_SECURITY_SECURITYPROTOCOL_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Security {

    enum class VNETSECURITYAPI SecurityProtocol : std::int32_t {

        UNSPECIFIED = 0,

        SSL_2_0 = 1,
        SSL_3_0 = 2,
        TLS_1_0 = 4,
        TLS_1_1 = 8,
        TLS_1_2 = 16,
        TLS_1_3 = 32,

    };

    static inline SecurityProtocol operator| (const SecurityProtocol lhs, const SecurityProtocol rhs) noexcept {
        return static_cast<SecurityProtocol>(static_cast<std::int32_t>(lhs) | static_cast<std::int32_t>(rhs));
    }

    static inline SecurityProtocol operator|= (SecurityProtocol& lhs, const SecurityProtocol rhs) noexcept {
        lhs = (lhs | rhs);
        return lhs;
    }

    static inline SecurityProtocol operator& (const SecurityProtocol lhs, const SecurityProtocol rhs) noexcept {
        return static_cast<SecurityProtocol>(static_cast<std::int32_t>(lhs) & static_cast<std::int32_t>(rhs));
    }

    static inline SecurityProtocol operator&= (SecurityProtocol& lhs, const SecurityProtocol rhs) noexcept {
        lhs = (lhs & rhs);
        return lhs;
    }

    static inline SecurityProtocol operator~ (const SecurityProtocol protocol) noexcept {
        return static_cast<SecurityProtocol>(~static_cast<std::int32_t>(protocol));
    }

}

#endif // _VNETSEC_SECURITY_SECURITYPROTOCOL_H_