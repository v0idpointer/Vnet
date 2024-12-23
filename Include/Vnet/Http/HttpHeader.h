/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPHEADER_H_
#define _VNETHTTP_HTTP_HTTPHEADER_H_

#include <Vnet/Exports.h>

#include <string>
#include <string_view>
#include <optional>

namespace Vnet::Http {
    
    class VNETHTTPAPI HttpHeader {

    private:
        std::string m_name;
        std::string m_value;

    public:
        HttpHeader(void);
        HttpHeader(const std::string_view name, const std::string_view value);
        HttpHeader(const HttpHeader& header);
        HttpHeader(HttpHeader&& header) noexcept;
        virtual ~HttpHeader(void);

        HttpHeader& operator= (const HttpHeader& header);
        HttpHeader& operator= (HttpHeader&& header) noexcept;
        bool operator== (const HttpHeader& header) const;

        const std::string& GetName(void) const;
        const std::string& GetValue(void) const;

        void SetName(const std::string_view name);
        void SetValue(const std::string_view value);

        std::string ToString(void) const;

    private:
        static std::optional<HttpHeader> ParseHeader(std::string_view str, const bool exceptions);

    public:
        static HttpHeader Parse(const std::string_view str);
        static std::optional<HttpHeader> TryParse(const std::string_view str);

    };

}

#endif // _VNETHTTP_HTTP_HTTPHEADER_H_