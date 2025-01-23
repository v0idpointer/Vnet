/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_HASHALGORITHM_H_
#define _VNETSEC_CRYPTOGRAPHY_HASHALGORITHM_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Cryptography {

    enum class VNETSECURITYAPI HashAlgorithm : std::uint32_t {

        SHA1,
        SHA256,
        SHA512,
        SHA3_256,
        SHA3_512,

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_HASHALGORITHM_H_