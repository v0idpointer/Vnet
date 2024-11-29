/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_POLLEVENT_H_
#define _VNETCORE_SOCKETS_POLLEVENT_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Sockets {

    enum class VNETCOREAPI PollEvent : std::int32_t {

        READ,
        WRITE,
        ERROR,

    };

}

#endif // _VNETCORE_SOCKETS_POLLEVENT_H_