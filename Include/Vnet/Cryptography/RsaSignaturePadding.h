/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_RSASIGNATUREPADDING_H_
#define _VNETSEC_CRYPTOGRAPHY_RSASIGNATUREPADDING_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Cryptography {

    enum class VNETSECURITYAPI RsaSignaturePadding : std::uint32_t {

        PKCS1,
        PSS,

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_RSASIGNATUREPADDING_H_