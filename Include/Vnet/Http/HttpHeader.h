/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPHEADER_H_
#define _VNETHTTP_HTTP_HTTPHEADER_H_

#include <Vnet/Exports.h>

#include <string>
#include <string_view>
#include <optional>

namespace Vnet::Http {
    
    /**
     * Represents an HTTP header.
     */
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

        /**
         * Returns the header name.
         * 
         * @returns A string.
         */
        const std::string& GetName(void) const;

        /**
         * Returns the header value.
         * 
         * @returns A string.
         */
        const std::string& GetValue(void) const;

        /**
         * Sets the header name.
         * 
         * @param name Header name.
         * @exception std::invalid_argument - The 'name' parameter is an empty string,
         * or 'name' contains invalid character(s).
         */
        void SetName(const std::string_view name);

        /**
         * Sets the header value.
         * 
         * @param value Header value.
         * @exception std::invalid_argument - The 'value' parameter contains invalid character(s).
         */
        void SetValue(const std::string_view value);

        /**
         * Returns the string representation of the HttpHeader object.
         * 
         * @returns A string.
         */
        std::string ToString(void) const;

    private:
        static std::optional<HttpHeader> ParseHeader(std::string_view str, const bool exceptions);

    public:

        /**
         * Parses an HTTP header.
         * 
         * @param str
         * @returns An HttpHeader.
         * @exception std::runtime_error - Bad HTTP header.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         */
        static HttpHeader Parse(const std::string_view str);

        /**
         * Tries to parse an HTTP header.
         * 
         * @param str
         * @returns If successful, an HttpHeader is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpHeader> TryParse(const std::string_view str);

    };

}

#endif // _VNETHTTP_HTTP_HTTPHEADER_H_