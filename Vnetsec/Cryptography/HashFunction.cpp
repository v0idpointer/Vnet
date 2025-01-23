/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef VNET_BUILD_VNETSEC
#define VNET_BUILD_VNETSEC
#endif

#include <Vnet/Cryptography/HashFunction.h>

#include <Vnet/Cryptography/MD5.h>
#include <Vnet/Cryptography/SHA1.h>
#include <Vnet/Cryptography/SHA256.h>
#include <Vnet/Cryptography/SHA512.h>
#include <Vnet/Cryptography/SHA3_256.h>
#include <Vnet/Cryptography/SHA3_512.h>

#include <openssl/evp.h>

#include <exception>
#include <stdexcept>

using namespace Vnet::Cryptography;

const std::unordered_map<HashAlgorithm, std::pair<HashFunction::DigestFnPtr, std::int32_t>> HashFunction::s_hashAlgorithms = { 
    
    { HashAlgorithm::MD5, { &MD5::Digest, MD5::DIGEST_SIZE } },
    { HashAlgorithm::SHA1, { &SHA1::Digest, SHA1::DIGEST_SIZE } },
    { HashAlgorithm::SHA256, { &SHA256::Digest, SHA256::DIGEST_SIZE } },
    { HashAlgorithm::SHA512, { &SHA512::Digest, SHA512::DIGEST_SIZE } },
    { HashAlgorithm::SHA3_256, { &SHA3_256::Digest, SHA3_256::DIGEST_SIZE } },
    { HashAlgorithm::SHA3_512, { &SHA3_512::Digest, SHA3_512::DIGEST_SIZE } },

};

const std::unordered_map<HashAlgorithm, const evp_md_st* (*)(void)> HashFunction::s_opensslEvpMds = {

    { HashAlgorithm::MD5, &EVP_md5 },
    { HashAlgorithm::SHA1, &EVP_sha1 },
    { HashAlgorithm::SHA256, &EVP_sha256 },
    { HashAlgorithm::SHA512, &EVP_sha512 },
    { HashAlgorithm::SHA3_256, &EVP_sha3_256 },
    { HashAlgorithm::SHA3_512, &EVP_sha3_512 },

};

std::vector<std::uint8_t> HashFunction::Digest(const HashAlgorithm hashAlg, const std::span<const std::uint8_t> data) {
    
    if (!HashFunction::s_hashAlgorithms.contains(hashAlg))
        throw std::invalid_argument("'hashAlg': Invalid hash algorithm.");

    std::vector<std::uint8_t> digest((HashFunction::s_hashAlgorithms.at(hashAlg).second / 8));
    HashFunction::Digest(hashAlg, data, digest);

    return digest;
}

void HashFunction::Digest(const HashAlgorithm hashAlg, const std::span<const std::uint8_t> data, const std::span<std::uint8_t> digest) {
    
    if (!HashFunction::s_hashAlgorithms.contains(hashAlg))
        throw std::invalid_argument("'hashAlg': Invalid hash algorithm.");

    HashFunction::s_hashAlgorithms.at(hashAlg).first(data, digest);

}

const evp_md_st* HashFunction::_GetOpensslEvpMd(const HashAlgorithm hashAlg) {

    if (!HashFunction::s_opensslEvpMds.contains(hashAlg))
        throw std::invalid_argument("'hashAlg': Invalid hash algorithm.");

    return HashFunction::s_opensslEvpMds.at(hashAlg)();
}