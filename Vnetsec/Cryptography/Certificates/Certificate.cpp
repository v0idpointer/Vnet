/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Cryptography/Certificates/Certificate.h>
#include <Vnet/Cryptography/KeyUtils.h>
#include <Vnet/Security/SecurityException.h>

#include <sstream>

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

using namespace Vnet;
using namespace Vnet::Cryptography;
using namespace Vnet::Cryptography::Certificates;
using namespace Vnet::Security;

Certificate::Certificate(NativeCertificate_t const cert, std::unique_ptr<CryptoKey>&& privateKey) noexcept
    : m_cert(cert), m_privateKey(std::move(privateKey)) { }

Certificate::Certificate() : Certificate(nullptr, nullptr) { }

Certificate::Certificate(Certificate&& cert) noexcept : Certificate(nullptr, nullptr) {
    this->operator= (std::move(cert));
}

Certificate::~Certificate() {

    if (this->m_cert != INVALID_CERTIFICATE_HANDLE) {
        X509_free(this->m_cert);
        this->m_cert = INVALID_CERTIFICATE_HANDLE;
    }

}

Certificate& Certificate::operator= (Certificate&& cert) noexcept {

    if (this != &cert) {

        if (this->m_cert != INVALID_CERTIFICATE_HANDLE) {
            X509_free(this->m_cert);
            this->m_cert = nullptr;
        }

        this->m_cert = cert.m_cert;
        cert.m_cert = INVALID_CERTIFICATE_HANDLE;
        
        this->m_privateKey = std::move(cert.m_privateKey);

    }

    return static_cast<Certificate&>(*this);
}

NativeCertificate_t Certificate::GetNativeCertificateHandle() const {
    return this->m_cert;
}

std::string Certificate::GetSubjectName() const {
    
    if (this->m_cert == INVALID_CERTIFICATE_HANDLE) 
        throw std::runtime_error("Invalid certificate.");

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
    
    if (this->m_cert == INVALID_CERTIFICATE_HANDLE) 
        throw std::runtime_error("Invalid certificate.");

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
    
    if (this->m_cert == INVALID_CERTIFICATE_HANDLE) 
        throw std::runtime_error("Invalid certificate.");
    
    ASN1_TIME* notBefore = X509_get_notBefore(this->m_cert);
    if (notBefore == nullptr) throw SecurityException(ERR_get_error());

    return ToDateTime(notBefore);
}

DateTime Certificate::GetNotAfter() const {
    
    if (this->m_cert == INVALID_CERTIFICATE_HANDLE) 
        throw std::runtime_error("Invalid certificate.");
    
    ASN1_TIME* notAfter = X509_get_notAfter(this->m_cert);
    if (notAfter == nullptr) throw SecurityException(ERR_get_error());

    return ToDateTime(notAfter);
}

std::int32_t Certificate::GetVersion() const {
    
    if (this->m_cert == INVALID_CERTIFICATE_HANDLE) 
        throw std::runtime_error("Invalid certificate.");

    return (X509_get_version(this->m_cert) + 1);
}

std::string Certificate::GetSerialNumber() const {

    if (this->m_cert == INVALID_CERTIFICATE_HANDLE) 
        throw std::runtime_error("Invalid certificate.");

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

    if (this->m_cert == INVALID_CERTIFICATE_HANDLE) 
        throw std::runtime_error("Invalid certificate.");

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
    
    if (this->m_cert == INVALID_CERTIFICATE_HANDLE) 
        throw std::runtime_error("Invalid certificate.");

    return (this->m_privateKey != nullptr);
}

const std::optional<std::reference_wrapper<const CryptoKey>> Certificate::GetPrivateKey() const {

    if (this->m_cert == INVALID_CERTIFICATE_HANDLE) 
        throw std::runtime_error("Invalid certificate.");

    if (this->m_privateKey) return std::cref(*this->m_privateKey);
    else return std::nullopt;
}

std::unique_ptr<CryptoKey> Certificate::GetPublicKey() const {

    if (this->m_cert == INVALID_CERTIFICATE_HANDLE) 
        throw std::runtime_error("Invalid certificate.");

    EVP_PKEY* publicKey = X509_get_pubkey(this->m_cert);
    if (publicKey == nullptr) throw SecurityException(ERR_get_error());

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        EVP_PKEY_free(publicKey);
        throw SecurityException(ERR_get_error());
    }

    if (PEM_write_bio_PUBKEY(bio, publicKey) != 1) {
        BIO_free(bio);
        EVP_PKEY_free(publicKey);
        throw SecurityException(ERR_get_error());
    }

    const char* str = nullptr;
    std::size_t len = BIO_get_mem_data(bio, &str);
    std::string pem = { str, len };

    BIO_free(bio);
    bio = nullptr;

    EVP_PKEY_free(publicKey);
    publicKey = nullptr;

    return KeyUtils::ImportPEM(pem, std::nullopt);
}

std::string Certificate::ExportPEM() const {

    if (this->m_cert == INVALID_CERTIFICATE_HANDLE) 
        throw std::runtime_error("Invalid certificate.");

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) throw SecurityException(ERR_get_error());

    if (PEM_write_bio_X509(bio, this->m_cert) != 1) {
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

Certificate Certificate::LoadCertificateFromPEM(const std::string_view certPem, const std::optional<std::reference_wrapper<const CryptoKey>> privateKey) {

    if (certPem.empty())
        throw std::invalid_argument("'certPem': Empty string.");

    if (privateKey.has_value() && (privateKey->get().GetNativeKeyHandle() == INVALID_KEY_HANDLE))
        throw std::invalid_argument("'privateKey': Invalid key.");

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) throw SecurityException(ERR_get_error());

    BIO_write(bio, certPem.data(), certPem.length());

    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    if (cert == nullptr) {
        BIO_free(bio);
        throw SecurityException(ERR_get_error());
    }

    BIO_free(bio);
    bio = nullptr;

    std::unique_ptr<CryptoKey> key = nullptr;

    if (privateKey.has_value()) {

        if (X509_check_private_key(cert, privateKey->get().GetNativeKeyHandle()) != 1) {
            X509_free(cert);
            throw SecurityException(-1, "Certificate and private key mismatch.");
        }

        try { key = KeyUtils::DuplicateKey(privateKey->get()); }
        catch (const std::invalid_argument&) {
            X509_free(cert);
            throw std::runtime_error("Unknown key type.");
        }
        catch (const SecurityException& ex) {
            X509_free(cert);
            throw ex;
        }

    }

    return { cert, std::move(key) };
}