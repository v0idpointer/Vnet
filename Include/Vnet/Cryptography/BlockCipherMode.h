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

        /** Cipher Feedback /w feedback size of 1 bit */
        CFB_1,

        /** Cipher Feedback /w feedback size of 8 bits */
        CFB_8,

        /** Cipher Feedback /w feedback size of 128 bits */
        CFB_128,

        /** Electronic Codebook */
        ECB,

        /** Output Feedback */
        OFB,

        /** Counter Mode */
        CTR,

        /** Galois/Counter Mode */
        GCM,

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_BLOCKCIPHERMODE_H_