/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETSEC_SECURITY_CERTIFICATE_H_
#define _VNETSEC_SECURITY_CERTIFICATE_H_

#include <Vnet/DateTime.h>

struct x509_st;
struct evp_pkey_st;

namespace Vnet::Security {

    class VNETSECURITYAPI Certificate {

    private:
        x509_st* m_cert;
        evp_pkey_st* m_privateKey;

    private:
        Certificate(x509_st* const cert, evp_pkey_st* const privateKey);

    public:
        Certificate(void);
        Certificate(const Certificate&) = delete;
        Certificate(Certificate&& cert) noexcept;
        virtual ~Certificate(void);

        Certificate& operator= (const Certificate&) = delete;
        Certificate& operator= (Certificate&& cert) noexcept;

        std::string GetSubjectName(void) const;
        std::string GetIssuerName(void) const;
        DateTime GetNotBefore(void) const;
        DateTime GetNotAfter(void) const;
        std::int32_t GetVersion(void) const;

    public:
        static Certificate LoadCertificateFromPEM(
            const std::string_view certPath, 
            const std::optional<std::string_view> privateKeyPath, 
            const std::optional<std::string_view> privateKeyPassword
        );

    };

}

#endif // _VNETSEC_SECURITY_CERTIFICATE_H_