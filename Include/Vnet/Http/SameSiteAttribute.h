/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_SAMESITEATTRIBUTE_H_
#define _VNETHTTP_HTTP_SAMESITEATTRIBUTE_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Http {
    
    enum class VNETHTTPAPI SameSiteAttribute : std::int16_t {

        STRICT,
        LAX,
        NONE,

    };

}

#endif // _VNETHTTP_HTTP_SAMESITEATTRIBUTE_H_