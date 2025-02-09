/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETWEB_NET_TRANSFERENCODING_H_
#define _VNETWEB_NET_TRANSFERENCODING_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Net {

    enum class VNETWEBAPI TransferEncoding : std::uint8_t {

        NONE = 0,
        CHUNKED = 1,

    };

}

#endif // _VNETWEB_NET_TRANSFERENCODING_H_