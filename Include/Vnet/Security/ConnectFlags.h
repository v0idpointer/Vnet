/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_SECURITY_CONNECTFLAGS_H_
#define _VNETSEC_SECURITY_CONNECTFLAGS_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Security {

    enum class VNETSECURITYAPI ConnectFlags : std::uint32_t {

        NONE = 0,

    };

    static inline ConnectFlags operator| (const ConnectFlags lhs, const ConnectFlags rhs) noexcept {
        return static_cast<ConnectFlags>(static_cast<std::uint32_t>(lhs) | static_cast<std::uint32_t>(rhs));
    }

    static inline ConnectFlags& operator|= (ConnectFlags& lhs, const ConnectFlags rhs) noexcept {
        lhs = (lhs | rhs);
        return lhs;
    }

    static inline ConnectFlags operator& (const ConnectFlags lhs, const ConnectFlags rhs) noexcept {
        return static_cast<ConnectFlags>(static_cast<std::uint32_t>(lhs) & static_cast<std::uint32_t>(rhs));
    }

    static inline ConnectFlags& operator&= (ConnectFlags& lhs, const ConnectFlags rhs) noexcept {
        lhs = (lhs & rhs);
        return lhs;
    }

    static inline ConnectFlags operator~ (const ConnectFlags flags) noexcept {
        return static_cast<ConnectFlags>(~static_cast<std::uint32_t>(flags));
    }

}

#endif // _VNETSEC_SECURITY_CONNECTFLAGS_H_