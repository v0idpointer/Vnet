/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_PROTOCOLTYPE_H_
#define _VNETCORE_SOCKETS_PROTOCOLTYPE_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Sockets {

    enum class VNETCOREAPI ProtocolType : std::int32_t {

        UNSPECIFIED,
        TCP,
        UDP,

    };

}

#endif // _VNETCORE_SOCKETS_PROTOCOLTYPE_H_