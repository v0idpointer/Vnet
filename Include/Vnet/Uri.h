/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETHTTP_URI_H_
#define _VNETHTTP_URI_H_

#include <Vnet/Exports.h>

#include <string>
#include <string_view>
#include <cstdint>
#include <optional>

namespace Vnet {

    class VNETHTTPAPI Uri {

    private:
        std::optional<std::string> m_scheme;
        std::optional<std::string> m_userInfo;
        std::optional<std::string> m_host;
        std::optional<std::uint16_t> m_port;
        std::optional<std::string> m_path;
        std::optional<std::string> m_query;
        std::optional<std::string> m_fragment;

    public:
        Uri(void);
        Uri(const Uri& uri);
        Uri(Uri&& uri) noexcept;
        virtual ~Uri(void);

        Uri& operator= (const Uri& uri);
        Uri& operator= (Uri&& uri) noexcept;
        bool operator== (const Uri& uri) const;

    public:
        const std::optional<std::string>& GetScheme(void) const;
        const std::optional<std::string>& GetUserInfo(void) const;
        const std::optional<std::string>& GetHost(void) const;
        const std::optional<std::uint16_t> GetPort(void) const;
        const std::optional<std::string>& GetPath(void) const;
        const std::optional<std::string>& GetQuery(void) const;
        const std::optional<std::string>& GetFragment(void) const;

        bool IsAbsoluteUri(void) const;
        bool IsRelativeUri(void) const;

        std::string ToString(void) const;

    private:
        static bool ContainsInvalidCharacters(const std::string_view uri);
        static std::optional<Uri> ParseUri(std::string_view str, const bool exceptions);

    public:
        static Uri Parse(const std::string_view str);
        static std::optional<Uri> TryParse(const std::string_view str);

        static std::string Encode(const std::string_view str);
        static std::string Encode(const std::string_view str, const bool encodePathDelimiters);
        static std::string Decode(const std::string_view str);
        static std::optional<std::string> TryDecode(const std::string_view str);

    };

}

#endif // _VNETHTTP_URI_H_