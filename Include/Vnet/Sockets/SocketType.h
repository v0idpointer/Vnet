/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_SOCKETTYPE_H_
#define _VNETCORE_SOCKETS_SOCKETTYPE_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Sockets {

    enum class VNETCOREAPI SocketType : std::int32_t {

        STREAM,
        DATAGRAM,
        RAW,
        RDM,
        SEQPACKET,

    };

}

#endif // _VNETCORE_SOCKETS_SOCKETTYPE_H_