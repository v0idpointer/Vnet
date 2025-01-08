/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_SECURITY_APPLICATIONTYPE_H_
#define _VNETSEC_SECURITY_APPLICATIONTYPE_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Security {

    enum class VNETSECURITYAPI ApplicationType : std::int8_t {

        CLIENT,
        SERVER,

    };

}

#endif // _VNETSEC_SECURITY_APPLICATIONTYPE_H_