/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_CRYPTOKEY_H_
#define _VNETSEC_CRYPTOGRAPHY_CRYPTOKEY_H_

#include <Vnet/Exports.h>

#include <string>
#include <string_view>
#include <optional>

struct evp_pkey_st;

namespace Vnet::Cryptography {

    typedef evp_pkey_st* NativeCryptoKey_t;
    constexpr NativeCryptoKey_t INVALID_KEY_HANDLE = nullptr;

    /**
     * Base class for all cryptographic keys.
     */
    class VNETSECURITYAPI CryptoKey {

    private:
        NativeCryptoKey_t m_key;

    protected:
        CryptoKey(NativeCryptoKey_t const key);

    public:
        CryptoKey(const CryptoKey&) = delete;
        CryptoKey(CryptoKey&& key) noexcept;
        virtual ~CryptoKey(void);

        CryptoKey& operator= (const CryptoKey&) = delete;
        CryptoKey& operator= (CryptoKey&& key) noexcept;
        bool operator== (const CryptoKey& key) const;

        NativeCryptoKey_t GetNativeKeyHandle(void) const;

    protected:
        static std::string ExportPublicKeyToPEM(const NativeCryptoKey_t key);
        static std::string ExportPrivateKeyToPEM(const NativeCryptoKey_t key, const std::optional<std::string_view> password);
        
        static NativeCryptoKey_t ImportPublicKeyFromPEM(const std::string_view pem);
        static NativeCryptoKey_t ImportPrivateKeyFromPEM(const std::string_view pem, const std::optional<std::string_view> password);

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_CRYPTOKEY_H_