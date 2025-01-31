/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Cryptography/Certificates/CertificateStore.h>
#include <Vnet/Cryptography/HashFunction.h>
#include <Vnet/Cryptography/KeyUtils.h>
#include <Vnet/Security/SecurityException.h>

#ifdef VNET_PLATFORM_WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wincrypt.h>
#include <ncrypt.h>
#endif

#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

using namespace Vnet::Cryptography::Certificates;
using namespace Vnet::Cryptography;
using namespace Vnet::Security;

CertificateStore::CertificateStore(NativeCertStore_t const certStore) : m_certStore(certStore) { }

CertificateStore::CertificateStore() : CertificateStore(INVALID_CERT_STORE_HANDLE) { }

CertificateStore::CertificateStore(CertificateStore&& certStore) noexcept : CertificateStore(INVALID_CERT_STORE_HANDLE) {
    this->operator= (std::move(certStore));
}

CertificateStore::~CertificateStore() {

    if (this->m_certStore != INVALID_CERT_STORE_HANDLE) {
        CertCloseStore(this->m_certStore, NULL);
        this->m_certStore = INVALID_CERT_STORE_HANDLE;
    }

}

CertificateStore& CertificateStore::operator= (CertificateStore&& certStore) noexcept {

    if (this != &certStore) {

        if (this->m_certStore != INVALID_CERT_STORE_HANDLE) {
            CertCloseStore(this->m_certStore, NULL);
            this->m_certStore = INVALID_CERT_STORE_HANDLE;
        }

        this->m_certStore = certStore.m_certStore;
        certStore.m_certStore = INVALID_CERT_STORE_HANDLE;

    }

    return static_cast<CertificateStore&>(*this);
}

NativeCertStore_t CertificateStore::GetNativeCertStoreHandle() const {
    return this->m_certStore;
}

#ifdef VNET_PLATFORM_WINDOWS

static std::string GetErrorMessage(const std::uint32_t errorCode) noexcept {

    LPSTR pszMessage = NULL;

	FormatMessageA(
		(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS),
		NULL,
		errorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPSTR>(&pszMessage),
		NULL,
		NULL
	);

    const std::string str = { pszMessage };
	LocalFree(pszMessage);
	pszMessage = NULL;

    return str;
}

/** Converts the Vnet's Certificate to Windows' PCCERT_CONTEXT */
static PCCERT_CONTEXT CertificateToWin32Cert(const Certificate& cert) {

    EVP_PKEY* pKey = nullptr;
    if (cert.HasPrivateKey())
        pKey = cert.GetPrivateKey()->get().GetNativeKeyHandle();

    PKCS12* pfx = PKCS12_create(
        "password", 
        "Vnetsec PFX", 
        pKey, 
        cert.GetNativeCertificateHandle(), 
        nullptr, 
        0, 
        0, 
        0, 
        0, 
        0
    );

    if (pfx == nullptr) throw SecurityException(ERR_get_error());

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        PKCS12_free(pfx);
        throw SecurityException(ERR_get_error());
    }

    if (i2d_PKCS12_bio(bio, pfx) != 1) {
        PKCS12_free(pfx);
        BIO_free(bio);
        throw SecurityException(ERR_get_error());
    }

    PKCS12_free(pfx);

    char* data = nullptr;
    std::size_t size = BIO_get_mem_data(bio, &data);

    CRYPT_DATA_BLOB pfxBlob = { 0 };
    pfxBlob.pbData = reinterpret_cast<BYTE*>(data);
    pfxBlob.cbData = static_cast<DWORD>(size);

    HCERTSTORE hStore = PFXImportCertStore(&pfxBlob, L"password", CRYPT_EXPORTABLE);
    if (hStore == nullptr) {
        BIO_free(bio);
        throw SecurityException(GetLastError(), GetErrorMessage(GetLastError()));
    }

    BIO_free(bio);

    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
        hStore, 
        (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING), 
        NULL, 
        CERT_FIND_ANY, 
        nullptr, 
        nullptr
    );

    if (pCertContext == nullptr) {
        CertCloseStore(hStore, NULL);
        throw SecurityException(GetLastError(), GetErrorMessage(GetLastError()));
    }

    CertCloseStore(hStore, NULL);

    return pCertContext;
}

/** Returns true if the certificate has a private key and if it's exportable. */
static bool IsPrivateKeyExportable(PCCERT_CONTEXT pCertContext) noexcept {

    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE keyHandle = NULL;
    DWORD keySpec = 0;
    BOOL callerFreeKeyHandle = FALSE;

    if (!CryptAcquireCertificatePrivateKey(
        pCertContext,
        (CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG),
        nullptr,
        &keyHandle,
        &keySpec,
        &callerFreeKeyHandle
    )) return false;

    if (keySpec == CERT_NCRYPT_KEY_SPEC) {
        
        DWORD exportPolicy = 0;
        DWORD size = 0;

        SECURITY_STATUS status = NCryptGetProperty(
            keyHandle,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            reinterpret_cast<BYTE*>(&exportPolicy),
            sizeof(exportPolicy),
            &size,
            NULL
        );

        if (status == ERROR_SUCCESS) {
            if (callerFreeKeyHandle) NCryptFreeObject(keyHandle);
            return static_cast<bool>(exportPolicy & NCRYPT_ALLOW_EXPORT_FLAG);
        }

    }

    if (callerFreeKeyHandle)
        NCryptFreeObject(keyHandle);

    return false;
}

/** Converts Windows' PCCERT_CONTEXT to Vnet's Certificate */
static Certificate Win32CertToCertificate(PCCERT_CONTEXT pCertContext) {
    
    if (!IsPrivateKeyExportable(pCertContext)) {

        const unsigned char* pbCertEncoded = pCertContext->pbCertEncoded;

        X509* cert = d2i_X509(nullptr, &pbCertEncoded, pCertContext->cbCertEncoded);
        if (cert == nullptr) throw SecurityException(ERR_get_error());

        BIO* bio = BIO_new(BIO_s_mem());
        if (bio == nullptr) {
            X509_free(cert);
            throw SecurityException(ERR_get_error());
        }

        if (PEM_write_bio_X509(bio, cert) != 1) {
            X509_free(cert);
            BIO_free(bio);
            throw SecurityException(ERR_get_error());
        }

        const char* str = nullptr;
        std::size_t len = BIO_get_mem_data(bio, &str);
        std::string pem = { str, len };

        X509_free(cert);
        BIO_free(bio);

        return Certificate::LoadCertificateFromPEM(pem, std::nullopt);
    }

    HCERTSTORE hMemStore = CertOpenStore(CERT_STORE_PROV_MEMORY, NULL, NULL, NULL, nullptr);
    if (hMemStore == nullptr) throw SecurityException(GetLastError(), GetErrorMessage(GetLastError()));

    if (!CertAddCertificateContextToStore(hMemStore, pCertContext, CERT_STORE_ADD_ALWAYS, nullptr)) {
        CertCloseStore(hMemStore, NULL);
        throw SecurityException(GetLastError(), GetErrorMessage(GetLastError()));
    }

    CRYPT_DATA_BLOB pfxBlob = { 0 };
    if (!PFXExportCertStoreEx(hMemStore, &pfxBlob, L"password", nullptr, EXPORT_PRIVATE_KEYS)) {
        CertCloseStore(hMemStore, NULL);
        throw SecurityException(GetLastError(), GetErrorMessage(GetLastError()));
    }

    pfxBlob.pbData = new BYTE[pfxBlob.cbData];
    if (!PFXExportCertStoreEx(hMemStore, &pfxBlob, L"password", nullptr, EXPORT_PRIVATE_KEYS)) {
        CertCloseStore(hMemStore, NULL);
        delete[] pfxBlob.pbData;
        throw SecurityException(GetLastError(), GetErrorMessage(GetLastError()));
    }

    CertCloseStore(hMemStore, NULL);

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        delete[] pfxBlob.pbData;
        throw SecurityException(ERR_get_error());
    }

    BIO_write(bio, pfxBlob.pbData, pfxBlob.cbData);
    delete[] pfxBlob.pbData;

    PKCS12* pfx = d2i_PKCS12_bio(bio, nullptr);
    if (pfx == nullptr) {
        BIO_free(bio);
        throw SecurityException(ERR_get_error());
    }

    X509* cert = nullptr;
    EVP_PKEY* pKey = nullptr;

    if (PKCS12_parse(pfx, "password", &pKey, &cert, nullptr) != 1) {
        PKCS12_free(pfx);
        BIO_free(bio);
        throw SecurityException(ERR_get_error());
    }

    PKCS12_free(pfx);
    BIO_free(bio);

    std::string certPem;
    std::string pKeyPem;

    bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        X509_free(cert);
        EVP_PKEY_free(pKey);
        throw SecurityException(ERR_get_error());
    }

    if (PEM_write_bio_X509(bio, cert) != 1) {
        BIO_free(bio);
        X509_free(cert);
        EVP_PKEY_free(pKey);
        throw SecurityException(ERR_get_error());
    }

    const char* str = nullptr;
    std::size_t len = BIO_get_mem_data(bio, &str);
    certPem = { str, len };

    BIO_reset(bio);

    if (PEM_write_bio_PrivateKey(bio, pKey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
        BIO_free(bio);
        X509_free(cert);
        EVP_PKEY_free(pKey);
        throw SecurityException(ERR_get_error());
    }

    len = BIO_get_mem_data(bio, &str);
    pKeyPem = { str, len };

    BIO_free(bio);
    X509_free(cert);
    EVP_PKEY_free(pKey);

    std::unique_ptr<CryptoKey> privateKey = nullptr;
    try { privateKey = KeyUtils::ImportPEM(pKeyPem, std::nullopt); }
    catch (const std::runtime_error&) { }

    if (privateKey) return Certificate::LoadCertificateFromPEM(certPem, *privateKey);
    else return Certificate::LoadCertificateFromPEM(certPem, std::nullopt);
}

#endif

std::vector<std::shared_ptr<Certificate>> CertificateStore::GetCertificates() const {

#ifdef VNET_PLATFORM_WINDOWS

    if (this->m_certStore == INVALID_CERT_STORE_HANDLE)
        throw std::runtime_error("Invalid certificate store.");

    std::vector<std::shared_ptr<Certificate>> certs = { };
    PCCERT_CONTEXT pCertContext = nullptr;
    while ((pCertContext = CertEnumCertificatesInStore(this->m_certStore, pCertContext)))
        certs.push_back(std::make_shared<Certificate>(Win32CertToCertificate(pCertContext)));

    return certs;
#else
    throw std::runtime_error("Operating system not supported.");
#endif

}

void CertificateStore::Add(const Certificate& cert) {
    
#ifdef VNET_PLATFORM_WINDOWS

    if (this->m_certStore == INVALID_CERT_STORE_HANDLE)
        throw std::runtime_error("Invalid certificate store.");

    if (cert.GetNativeCertificateHandle() == INVALID_CERTIFICATE_HANDLE)
        throw std::invalid_argument("'cert': Invalid certificate.");

    PCCERT_CONTEXT pCertContext = CertificateToWin32Cert(cert);
    if (!CertAddCertificateContextToStore(this->m_certStore, pCertContext, CERT_STORE_ADD_NEW, nullptr)) {

        CertFreeCertificateContext(pCertContext);

        if (GetLastError() == CRYPT_E_EXISTS) throw std::invalid_argument("'cert': The specified certificate already exists.");
        else throw SecurityException(GetLastError(), GetErrorMessage(GetLastError()));

    }

    CertFreeCertificateContext(pCertContext);

#else
    throw std::runtime_error("Operating system not supported.");
#endif

}

void CertificateStore::Remove(const Certificate& cert) {

#ifdef VNET_PLATFORM_WINDOWS
    
    if (this->m_certStore == INVALID_CERT_STORE_HANDLE)
        throw std::runtime_error("Invalid certificate store.");

    if (cert.GetNativeCertificateHandle() == INVALID_CERTIFICATE_HANDLE)
        throw std::invalid_argument("'cert': Invalid certificate.");

    const HashAlgorithm hashAlg = HashAlgorithm::SHA1;
    std::vector<std::uint8_t> digest(HashFunction::GetDigestSize(hashAlg));
    std::uint32_t n = 0;

    if (X509_digest(cert.GetNativeCertificateHandle(), HashFunction::_GetOpensslEvpMd(hashAlg), digest.data(), &n) != 1)
        throw SecurityException(ERR_get_error());

    CRYPT_HASH_BLOB hashBlob = { 0 };
    hashBlob.pbData = reinterpret_cast<BYTE*>(digest.data());
    hashBlob.cbData = static_cast<DWORD>(n);

    PCCERT_CONTEXT pCertContext = CertFindCertificateInStore(
        this->m_certStore,
        (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING),
        NULL,
        CERT_FIND_SHA1_HASH,
        &hashBlob,
        nullptr
    );

    if (pCertContext == nullptr) 
        throw std::invalid_argument("'cert': The specified certificate does not exist.");

    if (!CertDeleteCertificateFromStore(pCertContext))
        throw SecurityException(GetLastError(), GetErrorMessage(GetLastError()));

#else
    throw std::runtime_error("Operating system not supported.");
#endif

}

CertificateStore CertificateStore::OpenPersonalCertStore() {

#ifdef VNET_PLATFORM_WINDOWS

    NativeCertStore_t certStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM_W,
        NULL,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY"
    );

    if (certStore == nullptr)
        throw SecurityException(GetLastError(), GetErrorMessage(GetLastError()));

    return { certStore };
#else
    throw std::runtime_error("Operating system not supported.");
#endif

}