/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_SOCKETFLAGS_H_
#define _VNETCORE_SOCKETS_SOCKETFLAGS_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Sockets {

    enum class SocketFlags : std::int32_t {

        NONE = 0,

        OUT_OF_BAND,
        PEEK,
        DONT_ROUTE,
        TRUNCATED,
        CONTROL_DATA_TRUNCATED,
        WAIT_ALL,

    };

    static inline SocketFlags operator| (const SocketFlags lhs, const SocketFlags rhs) noexcept {
        return static_cast<SocketFlags>(static_cast<std::int32_t>(lhs) | static_cast<std::int32_t>(rhs));
    }

    static inline SocketFlags operator|= (SocketFlags& lhs, const SocketFlags rhs) noexcept {
        lhs = (lhs | rhs);
        return lhs;
    }

    static inline SocketFlags operator& (const SocketFlags lhs, const SocketFlags rhs) noexcept {
        return static_cast<SocketFlags>(static_cast<std::int32_t>(lhs) & static_cast<std::int32_t>(rhs));
    }

    static inline SocketFlags operator&= (SocketFlags& lhs, const SocketFlags rhs) noexcept {
        lhs = (lhs & rhs);
        return lhs;
    }

    static inline SocketFlags operator~ (const SocketFlags flag) noexcept {
        return static_cast<SocketFlags>(~static_cast<std::int32_t>(flag));
    }

}

#endif // _VNETCORE_SOCKETS_SOCKETFLAGS_H_