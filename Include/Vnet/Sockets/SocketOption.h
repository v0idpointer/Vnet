/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_SOCKETOPTION_H_
#define _VNETCORE_SOCKETS_SOCKETOPTION_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Sockets {

    enum class VNETCOREAPI SocketOption : std::int32_t {

        /* Socket level options */

        DEBUG,
        BROADCAST,
        REUSE_ADDRESS,
        KEEP_ALIVE,
        LINGER,
        OUT_OF_BAND_INLINE,
        SEND_BUFFER_SIZE,
        RECEIVE_BUFFER_SIZE,
        DONT_ROUTE,
        RECEIVE_LOW_WATERMARK,
        RECEIVE_TIMEOUT,
        SEND_LOW_WATERMARK,
        SEND_TIMEOUT,

    };

}

#endif // _VNETCORE_SOCKETS_SOCKETOPTION_H_