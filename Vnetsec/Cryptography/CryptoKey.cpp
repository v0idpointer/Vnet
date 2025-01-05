/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Cryptography/CryptoKey.h>
#include <Vnet/Security/SecurityException.h>

#include <cstring>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace Vnet::Cryptography;
using namespace Vnet::Security;

CryptoKey::CryptoKey(NativeCryptoKey_t const key) : m_key(key) { }

CryptoKey::CryptoKey(CryptoKey&& key) noexcept : CryptoKey(INVALID_KEY_HANDLE) {
    this->operator= (std::move(key));
}

CryptoKey::~CryptoKey() {

    if (this->m_key) {
        EVP_PKEY_free(this->m_key);
        this->m_key = INVALID_KEY_HANDLE;
    }

}

CryptoKey& CryptoKey::operator= (CryptoKey&& key) noexcept {

    if (this != &key) {

        if (this->m_key) {
            EVP_PKEY_free(this->m_key);
            this->m_key = INVALID_KEY_HANDLE;
        }

        this->m_key = key.m_key;
        key.m_key = INVALID_KEY_HANDLE;

    }

    return static_cast<CryptoKey&>(*this);
}

bool CryptoKey::operator== (const CryptoKey& key) const {
    
    if ((this->m_key == INVALID_KEY_HANDLE) && (key.m_key == INVALID_KEY_HANDLE)) return true;
    if ((this->m_key == INVALID_KEY_HANDLE) || (key.m_key == INVALID_KEY_HANDLE)) return false;

    return (EVP_PKEY_cmp(this->m_key, key.m_key) == 1);
}

NativeCryptoKey_t CryptoKey::GetNativeKeyHandle() const {
    return this->m_key;
}

std::string CryptoKey::ExportPublicKeyToPEM(const NativeCryptoKey_t key) {
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) throw SecurityException(ERR_get_error());

    if (PEM_write_bio_PUBKEY(bio, key) != 1) {
        BIO_free(bio);
        throw SecurityException(ERR_get_error());
    }

    const char* str = nullptr;
    std::size_t len = BIO_get_mem_data(bio, &str);
    std::string pem = { str, len };

    BIO_free(bio);
    bio = nullptr;

    return pem;
}

std::string CryptoKey::ExportPrivateKeyToPEM(const NativeCryptoKey_t key, const std::optional<std::string_view> password) {
    
    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) throw SecurityException(ERR_get_error());

    void* pwd = nullptr;
    const EVP_CIPHER* (*cipher)(void) = nullptr;

    if (password.has_value()) {
        pwd = const_cast<void*>(reinterpret_cast<const void*>(password->data()));
        cipher = &EVP_aes_256_cbc;
    }

    if (PEM_write_bio_PrivateKey(bio, key, (cipher ? cipher() : nullptr), nullptr, 0, nullptr, pwd) != 1) {
        BIO_free(bio);
        throw SecurityException(ERR_get_error());
    }

    const char* str = nullptr;
    std::size_t len = BIO_get_mem_data(bio, &str);
    std::string pem = { str, len };

    BIO_free(bio);
    bio = nullptr;

    return pem;
}

static inline std::int32_t StrLength(const char* str, const std::int32_t max) noexcept {

    if (str == nullptr) return 0;

    std::int32_t len = 0;
    while ((len < max) && (str[len] != 0x00)) ++len;

    return len;
}

static int OpenSsl_PasswordCallback(char* buf, int size, int rdflag, void* userdata) {
    
    const char* password = reinterpret_cast<const char*>(userdata);
    if (password != nullptr) {
        const int len = StrLength(password, size);
        memcpy(buf, password, len);
        return len;
    }

    return -1;
}

NativeCryptoKey_t CryptoKey::ImportPublicKeyFromPEM(const std::string_view pem) {

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) throw SecurityException(ERR_get_error());

    BIO_write(bio, pem.data(), pem.length());

    EVP_PKEY* publicKey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (publicKey == nullptr) {
        BIO_free(bio);
        throw SecurityException(ERR_get_error());
    }

    BIO_free(bio);
    bio = nullptr;

    return publicKey;
}

NativeCryptoKey_t CryptoKey::ImportPrivateKeyFromPEM(const std::string_view pem, const std::optional<std::string_view> password) {

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) throw SecurityException(ERR_get_error());

    BIO_write(bio, pem.data(), pem.length());

    void* pwd = nullptr;
    if (password.has_value()) 
        pwd = const_cast<void*>(reinterpret_cast<const void*>(password->data()));

    EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(bio, nullptr, &OpenSsl_PasswordCallback, pwd);
    if (privateKey == nullptr) {
        BIO_free(bio);
        throw SecurityException(ERR_get_error());
    }

    BIO_free(bio);
    bio = nullptr;

    return privateKey;
}