/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_SOCKETOPTIONLEVEL_H_
#define _VNETCORE_SOCKETS_SOCKETOPTIONLEVEL_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Sockets {

    enum class VNETCOREAPI SocketOptionLevel : std::int32_t {

        SOCKET,

    };

}

#endif // _VNETCORE_SOCKETS_SOCKETOPTIONLEVEL_H_