/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_RSAKEY_H_
#define _VNETSEC_CRYPTOGRAPHY_RSAKEY_H_

#include <Vnet/Cryptography/CryptoKey.h>
#include <Vnet/Cryptography/RsaKeyParameters.h>

namespace Vnet::Cryptography {

    class VNETSECURITYAPI RsaKey : public CryptoKey {
    
    private:
        RsaKey(NativeCryptoKey_t const key);

    public:
        RsaKey(void);
        RsaKey(RsaKey&& key) noexcept;
        virtual ~RsaKey(void);

        RsaKey& operator= (RsaKey&& key) noexcept;

        RsaKey DerivePublicKey(void) const;
        bool IsPrivateKey(void) const;
        bool IsPublicKey(void) const;

        RsaKeyParameters ExportParameters(void) const;
        std::string ExportPEM(const std::optional<std::string_view> password) const;

        static RsaKey ImportParameters(const RsaKeyParameters& params);
        static RsaKey ImportPEM(const std::string_view pem, const std::optional<std::string_view> password);

        static RsaKey Generate(const std::int32_t keySize);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_RSAKEY_H_