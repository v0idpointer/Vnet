/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_MD5_H_
#define _VNETSEC_CRYPTOGRAPHY_MD5_H_

#include <Vnet/Exports.h>

#include <cstdint>
#include <vector>
#include <span>

namespace Vnet::Cryptography {

    // Represents the MD5 hash algorithm.
    class VNETSECURITYAPI MD5 final {

    public:

        /**
         * Digest size (in bits).
         */
        static constexpr std::int32_t DIGEST_SIZE = 128;

        MD5(void) = delete;

        /**
         * Calculates the MD5 hash of the input data.
         * 
         * @param data The data to be hashed.
         * @returns An std::vector containing the hashed data.
         * @exception SecurityException
         */
        static std::vector<std::uint8_t> Digest(const std::span<const std::uint8_t> data);

        /**
         * Calculates the MD5 hash of the input data.
         * 
         * @param data The data to be hashed.
         * @param digest The buffer where the hashed data will be stored. This buffer must be at least 16 bytes (128 bits) in size.
         * @exception std::invalid_argument - The 'digest' buffer is too small.
         * @exception SecurityException
         */
        static void Digest(const std::span<const std::uint8_t> data, const std::span<std::uint8_t> digest);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_MD5_H_