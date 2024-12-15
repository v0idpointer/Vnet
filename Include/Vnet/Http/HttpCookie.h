/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPCOOKIE_H_
#define _VNETHTTP_HTTP_HTTPCOOKIE_H_

#include <Vnet/Exports.h>
#include <Vnet/DateTime.h>
#include <Vnet/Http/SameSiteAttribute.h>

namespace Vnet::Http {

    class VNETHTTPAPI HttpCookie {

    private:
        std::string m_name;
        std::string m_value;
        std::optional<DateTime> m_expirationDate;
        std::optional<std::int32_t> m_maxAge;
        std::optional<std::string> m_domain;
        std::optional<std::string> m_path;
        std::optional<bool> m_secure;
        std::optional<bool> m_httpOnly;
        std::optional<SameSiteAttribute> m_sameSite;

    public:
        HttpCookie(void);
        HttpCookie(const std::string_view name, const std::string_view value);
        HttpCookie(const HttpCookie& cookie);
        HttpCookie(HttpCookie&& cookie) noexcept;
        virtual ~HttpCookie(void);

        HttpCookie& operator= (const HttpCookie& cookie);
        HttpCookie& operator= (HttpCookie&& cookie) noexcept;
        bool operator== (const HttpCookie& cookie) const;

        const std::string& GetName(void) const;
        const std::string& GetValue(void) const;
        const std::optional<DateTime> GetExpirationDate(void) const;
        const std::optional<std::int32_t> GetMaxAge(void) const;
        const std::optional<std::string>& GetDomain(void) const;
        const std::optional<std::string>& GetPath(void) const;
        const std::optional<bool> IsSecure(void) const;
        const std::optional<bool> IsHttpOnly(void) const;
        const std::optional<SameSiteAttribute> GetSameSite(void) const;

        void SetName(const std::string_view name);
        void SetValue(const std::string_view value);
        void SetExpirationDate(const std::optional<DateTime> expirationDate);
        void SetMaxAge(const std::optional<std::int32_t> maxAge);
        void SetDomain(const std::optional<std::string_view> domain);
        void SetPath(const std::optional<std::string_view> path);
        void SetSecure(const std::optional<bool> secure);
        void SetHttpOnly(const std::optional<bool> httpOnly);
        void SetSameSite(const std::optional<SameSiteAttribute> sameSite);

        std::string ToString(void) const;

    };

}

#endif // _VNETHTTP_HTTP_HTTPCOOKIE_H_