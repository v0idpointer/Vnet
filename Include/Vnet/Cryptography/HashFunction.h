/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_HASHFUNCTION_H_
#define _VNETSEC_CRYPTOGRAPHY_HASHFUNCTION_H_

#include <Vnet/Cryptography/HashAlgorithm.h>

#include <unordered_map>
#include <vector>
#include <span>

struct evp_md_st;

namespace Vnet::Cryptography {

    class VNETSECURITYAPI HashFunction final {

    public:
        /**
         * A function pointer for the static Digest function found in various hash function classes.
         */
        using DigestFnPtr = void (*)(const std::span<const std::uint8_t>, const std::span<std::uint8_t>);

    private:
        static const std::unordered_map<HashAlgorithm, std::pair<HashFunction::DigestFnPtr, std::int32_t>> s_hashAlgorithms;
        static const std::unordered_map<HashAlgorithm, const evp_md_st* (*)(void)> s_opensslEvpMds;

    public:
        HashFunction(void) = delete;

        /**
         * Calculates the hash of the input data.
         * 
         * @param hashAlg Specifies what hash algorithm to use.
         * @param data The data to be hashed.
         * @returns An std::vector containing the hashed data.
         * @exception std::invalid_argument - Invalid hash algorithm specified.
         * @exception SecurityException
         */
        static std::vector<std::uint8_t> Digest(const HashAlgorithm hashAlg, const std::span<const std::uint8_t> data);

        /**
         * Calculates the hash of the input data.
         * 
         * @param hashAlg Specifies what hash algorithm to use.
         * @param data The data to be hashed.
         * @param digest The buffer where the hashed data will be stored.
         * @exception std::invalid_argument - Invalid hash algorithm specified, or the 'digest' buffer is too small.
         * @exception SecurityException
         */
        static void Digest(const HashAlgorithm hashAlg, const std::span<const std::uint8_t> data, const std::span<std::uint8_t> digest);

        /**
         * Returns the digest size (in bits).
         * 
         * @param hashAlg
         * @exception std::invalid_argument - Invalid hash algorithm specified.
         */
        static std::int32_t GetDigestSize(const HashAlgorithm hashAlg);

        static const evp_md_st* _GetOpensslEvpMd(const HashAlgorithm hashAlg);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_HASHFUNCTION_H_