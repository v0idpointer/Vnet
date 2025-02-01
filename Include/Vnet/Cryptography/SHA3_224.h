/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_SHA3_224_H_
#define _VNETSEC_CRYPTOGRAPHY_SHA3_224_H_

#include <Vnet/Exports.h>

#include <cstdint>
#include <vector>
#include <span>

namespace Vnet::Cryptography {

    /**
     * Represents the SHA3-224 hash algorithm.
     */
    class VNETSECURITYAPI SHA3_224 final {

    public:

        /**
         * Digest size (in bits).
         */
        static constexpr std::int32_t DIGEST_SIZE = 224;

        SHA3_224(void) = delete;

        /**
         * Calculates the SHA3-224 hash of the input data.
         * 
         * @param data The data to be hashed.
         * @returns An std::vector containing the hashed data.
         * @exception SecurityException
         */
        static std::vector<std::uint8_t> Digest(const std::span<const std::uint8_t> data);

        /**
         * Calculates the SHA3-224 hash of the input data.
         * 
         * @param data The data to be hashed.
         * @param digest The buffer where the hashed data will be stored. This buffer must be at least 28 bytes (224 bits) in size.
         * @exception std::invalid_argument - The 'digest' buffer is too small.
         * @exception SecurityException
         */
        static void Digest(const std::span<const std::uint8_t> data, const std::span<std::uint8_t> digest);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_SHA3_224_H_