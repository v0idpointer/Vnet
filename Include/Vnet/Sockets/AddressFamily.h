/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_ADDRESSFAMILY_H_
#define _VNETCORE_SOCKETS_ADDRESSFAMILY_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Sockets {

    enum class VNETCOREAPI AddressFamily : std::int32_t {

        UNSPECIFIED,

        /** Internet Protocol version 4 (IPv4) address family */
        IPV4,

        /** Internet Protocol version 6 (IPv6) address family */
        IPV6,

    };
    
}

#endif // _VNETCORE_SOCKETS_ADDRESSFAMILY_H_