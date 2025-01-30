/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_RSAENCRYPTIONPADDING_H_
#define _VNETSEC_CRYPTOGRAPHY_RSAENCRYPTIONPADDING_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Cryptography {

    enum class VNETSECURITYAPI RsaEncryptionPadding : std::uint32_t {

        NO_PADDING = 0,

        PKCS1,
        PKCS1_OAEP_SHA1,
        PKCS1_OAEP_SHA224,
        PKCS1_OAEP_SHA256,
        PKCS1_OAEP_SHA384,
        PKCS1_OAEP_SHA512,
        PKCS1_OAEP_SHA3_224,
        PKCS1_OAEP_SHA3_256,
        PKCS1_OAEP_SHA3_384,
        PKCS1_OAEP_SHA3_512,

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_RSAENCRYPTIONPADDING_H_