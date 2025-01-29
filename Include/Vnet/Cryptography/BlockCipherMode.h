/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_BLOCKCIPHERMODE_H_
#define _VNETSEC_CRYPTOGRAPHY_BLOCKCIPHERMODE_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Cryptography {

    enum class VNETSECURITYAPI BlockCipherMode : std::int32_t {

        /** Cipher Block Chaining */
        CBC,

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_BLOCKCIPHERMODE_H_