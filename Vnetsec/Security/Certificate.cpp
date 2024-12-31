/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/Security/Certificate.h>
#include <Vnet/Security/SecurityException.h>

#include <cstring>
#include <sstream>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

using namespace Vnet;
using namespace Vnet::Security;

Certificate::Certificate(x509_st* const cert, evp_pkey_st* const privateKey)
    : m_cert(cert), m_privateKey(privateKey) { }

Certificate::Certificate() : Certificate(nullptr, nullptr) { }

Certificate::Certificate(Certificate&& cert) noexcept : Certificate(nullptr, nullptr) {
    this->operator= (std::move(cert));
}

Certificate::~Certificate() {

    if (this->m_cert) {
        X509_free(this->m_cert);
        this->m_cert = nullptr;
    }

    if (this->m_privateKey) {
        EVP_PKEY_free(this->m_privateKey);
        this->m_privateKey = nullptr;
    }

}

Certificate& Certificate::operator= (Certificate&& cert) noexcept {

    if (this != &cert) {

        if (this->m_cert) {
            X509_free(this->m_cert);
            this->m_cert = nullptr;
        }

        if (this->m_privateKey) {
            EVP_PKEY_free(this->m_privateKey);
            this->m_privateKey = nullptr;
        }

        this->m_cert = cert.m_cert;
        this->m_privateKey = cert.m_privateKey;

        cert.m_cert = nullptr;
        cert.m_privateKey = nullptr;

    }

    return static_cast<Certificate&>(*this);
}

std::string Certificate::GetSubjectName() const {
    
    if (this->m_cert == nullptr) throw std::runtime_error("Invalid certificate.");

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) throw SecurityException(ERR_get_error());

    if (X509_NAME_print_ex(bio, X509_get_subject_name(this->m_cert), 0, XN_FLAG_RFC2253) <= 0) {
        BIO_free(bio);
        throw SecurityException(ERR_get_error());
    }

    const char* str = nullptr;
    std::size_t len = BIO_get_mem_data(bio, &str);
    std::string subjectName = { str, len };

    BIO_free(bio);
    bio = nullptr;

    return subjectName;
}

std::string Certificate::GetIssuerName() const {
    
    if (this->m_cert == nullptr) throw std::runtime_error("Invalid certificate.");

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) throw SecurityException(ERR_get_error());

    if (X509_NAME_print_ex(bio, X509_get_issuer_name(this->m_cert), 0, XN_FLAG_RFC2253) <= 0) {
        BIO_free(bio);
        throw SecurityException(ERR_get_error());
    }

    const char* str = nullptr;
    std::size_t len = BIO_get_mem_data(bio, &str);
    std::string issuerName = { str, len };

    BIO_free(bio);
    bio = nullptr;

    return issuerName;
}

static inline DateTime ToDateTime(ASN1_TIME* const time) noexcept {

    std::tm tm = { 0 };
    ASN1_TIME_to_tm(time, &tm);

    DateTime dateTime = { std::mktime(&tm) };
    dateTime += std::chrono::seconds(DateTime::Now().GetTimezoneOffset());

    return dateTime;
}

DateTime Certificate::GetNotBefore() const {
    
    if (this->m_cert == nullptr) throw std::runtime_error("Invalid certificate.");
    
    ASN1_TIME* notBefore = X509_get_notBefore(this->m_cert);
    if (notBefore == nullptr) throw SecurityException(ERR_get_error());

    return ToDateTime(notBefore);
}

DateTime Certificate::GetNotAfter() const {
    
    if (this->m_cert == nullptr) throw std::runtime_error("Invalid certificate.");
    
    ASN1_TIME* notAfter = X509_get_notAfter(this->m_cert);
    if (notAfter == nullptr) throw SecurityException(ERR_get_error());

    return ToDateTime(notAfter);
}

std::int32_t Certificate::GetVersion() const {
    if (this->m_cert == nullptr) throw std::runtime_error("Invalid certificate.");
    return (X509_get_version(this->m_cert) + 1);
}

std::string Certificate::GetSerialNumber() const {

    if (this->m_cert == nullptr) throw std::runtime_error("Invalid certificate.");

    ASN1_INTEGER* serialNumber = X509_get_serialNumber(this->m_cert);
    if (serialNumber == nullptr) throw SecurityException(ERR_get_error());
    
    BIGNUM* bn = ASN1_INTEGER_to_BN(serialNumber, nullptr);
    if (bn == nullptr) throw SecurityException(ERR_get_error());

    char* str = BN_bn2hex(bn);
    std::string serialNumberStr = { str };

    OPENSSL_free(str);
    BN_free(bn);

    return serialNumberStr;
}

std::string Certificate::GetThumbprint() const {

    if (this->m_cert == nullptr) throw std::runtime_error("Invalid certificate.");

    std::uint8_t digest[SHA_DIGEST_LENGTH] = { 0 };
    std::uint32_t n = 0;

    if (X509_digest(this->m_cert, EVP_sha1(), digest, &n) <= 0)
        throw SecurityException(ERR_get_error());

    std::ostringstream stream;
    for (std::uint32_t i = 0; i < n; ++i)
        stream << std::hex << std::uppercase << static_cast<std::int32_t>(digest[i]);

    return stream.str();
}

bool Certificate::HasPrivateKey() const {
    if (this->m_cert == nullptr) throw std::runtime_error("Invalid certificate.");
    else return (this->m_privateKey != nullptr);
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

Certificate Certificate::LoadCertificateFromPEM(
    const std::string_view certPath, 
    const std::optional<std::string_view> privateKeyPath, 
    const std::optional<std::string_view> privateKeyPassword
) {

    if (certPath.empty()) 
        throw std::invalid_argument("'certPath': empty string.");

    if (privateKeyPath.has_value() && privateKeyPath->empty())
        throw std::invalid_argument("'privateKeyPath': empty string.");

    BIO* bio = nullptr;
    X509* cert = nullptr;
    EVP_PKEY* privateKey = nullptr;

    bio = BIO_new_file(certPath.data(), "r");
    if (bio == nullptr) throw SecurityException(ERR_get_error());

    cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    bio = nullptr;

    if (cert == nullptr) throw SecurityException(ERR_get_error());

    if (privateKeyPath.has_value()) {
        
        bio = BIO_new_file(privateKeyPath->data(), "r");
        if (bio == nullptr) {
            X509_free(cert);
            throw SecurityException(ERR_get_error());
        }

        void* password = nullptr;
        if (privateKeyPassword.has_value())
            password = const_cast<void*>(reinterpret_cast<const void*>(privateKeyPassword->data()));

        privateKey = PEM_read_bio_PrivateKey(bio, nullptr, OpenSsl_PasswordCallback, password);
        BIO_free(bio);
        bio = nullptr;

        if (privateKey == nullptr) {
            X509_free(cert);
            throw SecurityException(ERR_get_error());
        }

        if (X509_check_private_key(cert, privateKey) != 1) {
            X509_free(cert);
            EVP_PKEY_free(privateKey);
            throw SecurityException(-1, "Certificate and private key mismatch.");
        }

    }

    return { cert, privateKey };
}