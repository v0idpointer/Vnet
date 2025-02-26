/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPHEADER_H_
#define _VNETHTTP_HTTP_HTTPHEADER_H_

#include <Vnet/Http/HttpParserOptions.h>

#include <string>
#include <string_view>

namespace Vnet::Http {
    
    /**
     * Represents an HTTP header.
     */
    class VNETHTTPAPI HttpHeader {

    private:
        std::string m_name;
        std::string m_value;

    public:

        /**
         * Constructs a new HttpHeader object.
         * 
         * The name of the newly created header is "x-my-header",
         * and the value is an empty string.
         */
        HttpHeader(void);

        /**
         * Constructs a new HttpHeader object.
         * 
         * @param name Header name.
         * @param value Header value.
         * @exception std::invalid_argument - The 'name' parameter is an empty string,
         * or 'name' contains an invalid header name, or the 'value' parameter
         * contains an invalid header value.
         */
        HttpHeader(const std::string_view name, const std::string_view value);
        
        /**
         * Constructs a new HttpHeader object by copying an existing one.
         * 
         * @param header An HttpHeader object to copy.
         */
        HttpHeader(const HttpHeader& header);
        
        HttpHeader(HttpHeader&& header) noexcept;
        virtual ~HttpHeader(void);

        /**
         * Assigns the value from an existing HttpHeader object to this object.
         * 
         * @param header An HttpHeader object to copy.
         */
        HttpHeader& operator= (const HttpHeader& header);
        
        HttpHeader& operator= (HttpHeader&& header) noexcept;
        
        /**
         * Compares this HttpHeader object with another for equality.
         * 
         * @param header An HttpHeader object to compare with.
         * @returns true if the HttpHeader objects are equal; otherwise, false.
         */
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
         * or 'name' contains an invalid header name.
         */
        void SetName(const std::string_view name);

        /**
         * Sets the header value.
         * 
         * @param value Header value.
         * @exception std::invalid_argument - The 'value' parameter contains an invalid header value.
         */
        void SetValue(const std::string_view value);

        /**
         * Returns the string representation of the HttpHeader object.
         * 
         * @returns A string.
         */
        std::string ToString(void) const;

    private:
        static std::optional<HttpHeader> ParseHeader(std::string_view str, const HttpParserOptions& options, const bool exceptions);

    public:

        /**
         * Parses an HTTP header.
         * 
         * @param str A string containing an HTTP header.
         * @returns An HttpHeader.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         * @exception HttpParserException - An error has occurred while parsing an HTTP header.
         */
        static HttpHeader Parse(const std::string_view str);

        /**
         * Parses an HTTP header.
         * 
         * @param str A string containing an HTTP header.
         * @param options Options for the HTTP parser.
         * @returns An HttpHeader.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         * @exception HttpParserException - An error has occurred while parsing an HTTP header.
         */
        static HttpHeader Parse(const std::string_view str, const HttpParserOptions& options);

        /**
         * Tries to parse an HTTP header.
         * 
         * @param str A string containing an HTTP header.
         * @returns If successful, an HttpHeader is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpHeader> TryParse(const std::string_view str);

        /**
         * Tries to parse an HTTP header.
         * 
         * @param str A string containing an HTTP header.
         * @param options Options for the HTTP parser.
         * @returns If successful, an HttpHeader is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpHeader> TryParse(const std::string_view str, const HttpParserOptions& options);

    };

}

#endif // _VNETHTTP_HTTP_HTTPHEADER_H_