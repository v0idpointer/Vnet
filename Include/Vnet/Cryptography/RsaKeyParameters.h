/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_RSAKEYPARAMETERS_H_
#define _VNETSEC_CRYPTOGRAPHY_RSAKEYPARAMETERS_H_

#include <Vnet/Exports.h>

#include <cstdint>
#include <vector>
#include <optional>

namespace Vnet::Cryptography {

    struct VNETSECURITYAPI RsaKeyParameters {

        /* public key parameters */

        std::optional<std::vector<std::uint8_t>> Modulus;           // n
        std::optional<std::vector<std::uint8_t>> PublicExponent;    // e

        /* private key parameters */

        std::optional<std::vector<std::uint8_t>> PrivateExponent;   // d
        std::optional<std::vector<std::uint8_t>> Prime1;            // p
        std::optional<std::vector<std::uint8_t>> Prime2;            // q
        std::optional<std::vector<std::uint8_t>> Exponent1;         // dmp1
        std::optional<std::vector<std::uint8_t>> Exponent2;         // dmp2
        std::optional<std::vector<std::uint8_t>> Coefficient;       // iqmp

        RsaKeyParameters(void);
        RsaKeyParameters(const RsaKeyParameters& params);
        RsaKeyParameters(RsaKeyParameters&& params) noexcept;
        virtual ~RsaKeyParameters(void);

        RsaKeyParameters& operator= (const RsaKeyParameters& params);
        RsaKeyParameters& operator= (RsaKeyParameters&& params) noexcept;
        bool operator== (const RsaKeyParameters& params) const;

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_RSAKEYPARAMETERS_H_