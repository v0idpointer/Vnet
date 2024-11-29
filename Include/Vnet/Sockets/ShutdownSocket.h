/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_SHUTDOWNSOCKET_H_
#define _VNETCORE_SOCKETS_SHUTDOWNSOCKET_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Sockets {

    enum class VNETCOREAPI ShutdownSocket : std::int32_t {

        RECEIVE,
		SEND,
		BOTH,

    };

}

#endif // _VNETCORE_SOCKETS_SHUTDOWNSOCKET_H_