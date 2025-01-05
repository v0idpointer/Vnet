/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Cryptography/RsaKey.h>
#include <Vnet/Security/SecurityException.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace Vnet::Cryptography;
using namespace Vnet::Security;

RsaKey::RsaKey(NativeCryptoKey_t const key) : CryptoKey(key) { }

RsaKey::RsaKey() : RsaKey(INVALID_KEY_HANDLE) { }

RsaKey::RsaKey(RsaKey&& key) noexcept : RsaKey(INVALID_KEY_HANDLE) {
    this->operator= (std::move(key));
}

RsaKey::~RsaKey() { }

RsaKey& RsaKey::operator= (RsaKey&& key) noexcept {
    CryptoKey::operator= (std::move(key));
    return static_cast<RsaKey&>(*this);
}

RsaKey RsaKey::DerivePublicKey() const {

    if (this->GetNativeKeyHandle() == INVALID_KEY_HANDLE)
        throw std::runtime_error("Invalid key.");

    const RSA* rsaPrivate = EVP_PKEY_get0_RSA(this->GetNativeKeyHandle());
    if (rsaPrivate == nullptr) throw SecurityException(ERR_get_error());

    RSA* rsaPublic = RSA_new();
    if (rsaPublic == nullptr) throw SecurityException(ERR_get_error());

    const BIGNUM *n, *e;
    RSA_get0_key(rsaPrivate, &n, &e, nullptr);

    if (RSA_set0_key(rsaPublic, BN_dup(n), BN_dup(e), nullptr) != 1) {
        RSA_free(rsaPublic);
        throw SecurityException(ERR_get_error());
    }

    EVP_PKEY* publicKey = EVP_PKEY_new();
    if (publicKey == nullptr) {
        RSA_free(rsaPublic);
        throw SecurityException(ERR_get_error());
    }

    if (EVP_PKEY_assign_RSA(publicKey, rsaPublic) != 1) {
        RSA_free(rsaPublic);
        EVP_PKEY_free(publicKey);
        throw SecurityException(ERR_get_error());
    }

    return { publicKey };
}

bool RsaKey::IsPrivateKey() const {
    const RsaKeyParameters params = this->ExportParameters();
    return (params.Modulus.has_value() && params.PublicExponent.has_value() && params.PrivateExponent.has_value());
}

bool RsaKey::IsPublicKey() const {
    return !this->IsPrivateKey();
}

static inline std::optional<std::vector<std::uint8_t>> BignumToVector(const BIGNUM* bignum) noexcept {

    if (bignum == nullptr) return std::nullopt;

    std::size_t len = BN_num_bytes(bignum);
    std::vector<std::uint8_t> data(len);

    BN_bn2bin(bignum, data.data());

    return data;
}

static inline BIGNUM* VectorToBignum(const std::optional<std::vector<std::uint8_t>>& vector) noexcept {
    if (!vector.has_value()) return nullptr;
    else return BN_bin2bn(vector->data(), vector->size(), nullptr);
}

RsaKeyParameters RsaKey::ExportParameters() const {

    if (this->GetNativeKeyHandle() == INVALID_KEY_HANDLE)
        throw std::runtime_error("Invalid key.");

    const RSA* rsa = EVP_PKEY_get0_RSA(this->GetNativeKeyHandle());
    if (rsa == nullptr) throw SecurityException(ERR_get_error());

    const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmp2, *iqmp;
    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmp2, &iqmp);

    RsaKeyParameters params = { };
    params.Modulus = BignumToVector(n);
    params.PublicExponent = BignumToVector(e);
    params.PrivateExponent = BignumToVector(d);
    params.Prime1 = BignumToVector(p);
    params.Prime2 = BignumToVector(q);
    params.Exponent1 = BignumToVector(dmp1);
    params.Exponent2 = BignumToVector(dmp2);
    params.Coefficient = BignumToVector(iqmp);

    return params;
}

std::string RsaKey::ExportPEM(const std::optional<std::string_view> password) const {

    if (this->GetNativeKeyHandle() == INVALID_KEY_HANDLE)
        throw std::runtime_error("Invalid key.");

    const bool publicKey = this->IsPublicKey();

    if (publicKey && password.has_value())
        throw std::invalid_argument("'password': Cannot encrypt the RSA public key.");

    if (publicKey) return CryptoKey::ExportPublicKeyToPEM(this->GetNativeKeyHandle());
    else return CryptoKey::ExportPrivateKeyToPEM(this->GetNativeKeyHandle(), password);
}

static inline void FreeParams(BIGNUM* n, BIGNUM* e, BIGNUM* d, BIGNUM* p, BIGNUM* q, BIGNUM* dmp1, BIGNUM* dmp2, BIGNUM* iqmp) {
    
    if (n != nullptr) BN_free(n);
    if (e != nullptr) BN_free(e);
    if (d != nullptr) BN_free(d);
    if (p != nullptr) BN_free(p);
    if (q != nullptr) BN_free(q);
    if (dmp1 != nullptr) BN_free(dmp1);
    if (dmp2 != nullptr) BN_free(dmp2);
    if (iqmp != nullptr) BN_free(iqmp);

}

RsaKey RsaKey::ImportParameters(const RsaKeyParameters& params) {

    RSA* rsa = RSA_new();
    if (rsa == nullptr) throw SecurityException(ERR_get_error());

    BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmp2, *iqmp;    
    n = VectorToBignum(params.Modulus);
    e = VectorToBignum(params.PublicExponent);
    d = VectorToBignum(params.PrivateExponent);
    p = VectorToBignum(params.Prime1);
    q = VectorToBignum(params.Prime2);
    dmp1 = VectorToBignum(params.Exponent1);
    dmp2 = VectorToBignum(params.Exponent2);
    iqmp = VectorToBignum(params.Coefficient);

    if (RSA_set0_key(rsa, n, e, d) != 1) {
        RSA_free(rsa);
        FreeParams(n, e, d, p, q, dmp1, dmp2, iqmp);
        throw SecurityException(ERR_get_error());
    }

    if (RSA_set0_factors(rsa, p, q) != 1) {
        RSA_free(rsa);
        FreeParams(n, e, d, p, q, dmp1, dmp2, iqmp);
        throw SecurityException(ERR_get_error());
    }

    if (RSA_set0_crt_params(rsa, dmp1, dmp2, iqmp) != 1) {
        RSA_free(rsa);
        FreeParams(n, e, d, p, q, dmp1, dmp2, iqmp);
        throw SecurityException(ERR_get_error());
    }

    EVP_PKEY* key = EVP_PKEY_new();
    if (key == nullptr) {
        RSA_free(rsa);
        throw SecurityException(ERR_get_error());
    }

    if (EVP_PKEY_assign_RSA(key, rsa) != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(key);
        throw SecurityException(ERR_get_error());
    }

    return { key };
}

RsaKey RsaKey::ImportPEM(const std::string_view pem, const std::optional<std::string_view> password) {

    if (pem.empty()) throw std::invalid_argument("'pem': Empty string.");

    const std::string_view marker = pem.substr(0, pem.find("\n"));
    const bool privateKey = (marker.find("PRIVATE KEY") != std::string_view::npos);
    const bool encrypted = (marker.find("ENCRYPTED PRIVATE KEY") != std::string_view::npos);

    if (encrypted && !password.has_value())
        throw std::invalid_argument("'password': Cannot decrypt the RSA private key. Password not provided.");

    NativeCryptoKey_t key = INVALID_KEY_HANDLE;
    if (privateKey) key = CryptoKey::ImportPrivateKeyFromPEM(pem, password);
    else key = CryptoKey::ImportPublicKeyFromPEM(pem);

    if (EVP_PKEY_base_id(key) != EVP_PKEY_RSA) {
        EVP_PKEY_free(key);
        throw std::runtime_error("The specified key is not a valid RSA key.");
    }

    return { key };
}

RsaKey RsaKey::Generate(const std::int32_t keySize) {

    BIGNUM* bn = BN_new();
    if (bn == nullptr) throw SecurityException(ERR_get_error());

    if (BN_set_word(bn, RSA_F4) != 1) {
        BN_free(bn);
        throw SecurityException(ERR_get_error());
    }

    RSA* rsa = RSA_new();
    if (rsa == nullptr) {
        BN_free(bn);
        throw SecurityException(ERR_get_error());
    }

    if (RSA_generate_key_ex(rsa, keySize, bn, nullptr) != 1) {
        RSA_free(rsa);
        BN_free(bn);
        throw SecurityException(ERR_get_error());
    }

    EVP_PKEY* key = EVP_PKEY_new();
    if (key == nullptr) {
        RSA_free(rsa);
        BN_free(bn);
        throw SecurityException(ERR_get_error());
    }

    if (EVP_PKEY_assign_RSA(key, rsa) != 1) {
        EVP_PKEY_free(key);
        RSA_free(rsa);
        BN_free(bn);
        throw SecurityException(ERR_get_error());
    }

    BN_free(bn);

    return { key };
}