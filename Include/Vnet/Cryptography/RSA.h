/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_RSA_H_
#define _VNETSEC_CRYPTOGRAPHY_RSA_H_

#include <Vnet/Cryptography/RsaKey.h>

#include <span>

namespace Vnet::Cryptography {

    /**
     * Represents the RSA (Rivest–Shamir–Adleman) cryptographic algorithm.
     */
    class VNETSECURITYAPI RSA final {

    public:
        RSA(void) = delete;

        static std::vector<std::uint8_t> Encrypt(const RsaKey& key, const std::span<const std::uint8_t> data);
        static std::vector<std::uint8_t> Decrypt(const RsaKey& privateKey, const std::span<const std::uint8_t> encryptedData);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_RSA_H_