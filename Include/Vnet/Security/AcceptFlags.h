/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_SECURITY_ACCEPTFLAGS_H_
#define _VNETSEC_SECURITY_ACCEPTFLAGS_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Security {

    enum class VNETSECURITYAPI AcceptFlags : std::uint32_t {

        NONE = 0,

        MUTUAL_AUTHENTICATION = 1

    };

    static inline AcceptFlags operator| (const AcceptFlags lhs, const AcceptFlags rhs) noexcept {
        return static_cast<AcceptFlags>(static_cast<std::uint32_t>(lhs) | static_cast<std::uint32_t>(rhs));
    }

    static inline AcceptFlags& operator|= (AcceptFlags& lhs, const AcceptFlags rhs) noexcept {
        lhs = (lhs | rhs);
        return lhs;
    }

    static inline AcceptFlags operator& (const AcceptFlags lhs, const AcceptFlags rhs) noexcept {
        return static_cast<AcceptFlags>(static_cast<std::uint32_t>(lhs) & static_cast<std::uint32_t>(rhs));
    }

    static inline AcceptFlags& operator&= (AcceptFlags& lhs, const AcceptFlags rhs) noexcept {
        lhs = (lhs & rhs);
        return lhs;
    }

    static inline AcceptFlags operator~ (const AcceptFlags flags) noexcept {
        return static_cast<AcceptFlags>(~static_cast<std::uint32_t>(flags));
    }

}

#endif // _VNETSEC_SECURITY_ACCEPTFLAGS_H_