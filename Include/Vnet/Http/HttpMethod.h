/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPMETHOD_H_
#define _VNETHTTP_HTTP_HTTPMETHOD_H_

#include <Vnet/Http/HttpParserOptions.h>

#include <string>
#include <string_view>

namespace Vnet::Http {

    /**
     * Represents an HTTP request method.
     */
    class VNETHTTPAPI HttpMethod {

    public:
        static const HttpMethod GET;
        static const HttpMethod HEAD;
        static const HttpMethod POST;
        static const HttpMethod PUT;
        static const HttpMethod DELETE;
        static const HttpMethod CONNECT;
        static const HttpMethod OPTIONS;
        static const HttpMethod TRACE;
        static const HttpMethod PATCH;

    private:
        std::string m_name;

    public:

        /**
         * Constructs a new HttpMethod object.
         * 
         * @param name Method name.
         * @exception std::invalid_argument - The 'name' parameter is an empty string,
         * or 'name' contains an invalid request method name.
         */
        HttpMethod(const std::string_view name);
        
        /**
         * Constructs a new HttpMethod object by copying an existing one.
         * 
         * @param method An HttpMethod object to copy.
         */
        HttpMethod(const HttpMethod& method);
        
        HttpMethod(HttpMethod&& method) noexcept;
        virtual ~HttpMethod(void);

        /**
         * Assigns the value from an existing HttpMethod object to this object.
         * 
         * @param method An HttpMethod object to copy.
         */
        HttpMethod& operator= (const HttpMethod& method);
        
        HttpMethod& operator= (HttpMethod&& method) noexcept;
        
        /**
         * Compares this HttpMethod object with another for equality.
         * 
         * @param An HttpMethod object to compare with.
         * @returns true if the HttpMethod objects are equal; otherwise, false.
         */
        bool operator== (const HttpMethod& method) const;

        /**
         * Returns the name of the request method.
         * 
         * @returns A string.
         */
        const std::string& GetName(void) const;

        /**
         * Sets the request method name.
         * 
         * @param name Method name.
         * @exception std::invalid_argument - The 'name' parameter is an empty string,
         * or 'name' contains an invalid request method name.
         */
        void SetName(const std::string_view name);

        /**
         * Returns the string representation of the HttpMethod object.
         * 
         * @returns A string. 
         */
        std::string ToString(void) const;

    private:
        static std::optional<HttpMethod> ParseMethod(const std::string_view str, const HttpParserOptions& options, const bool exceptions);

    public:

        /**
         * Parses an HTTP request method.
         * 
         * @param str A string containing an HTTP request method.
         * @returns An HttpMethod.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         * @exception HttpParserException - An error has occurred while parsing an HTTP request method.
         */
        static HttpMethod Parse(const std::string_view str);

        /**
         * Parses an HTTP request method.
         * 
         * @param str A string containing an HTTP request method.
         * @param options Options for the HTTP parser.
         * @returns An HttpMethod.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         * @exception HttpParserException - An error has occurred while parsing an HTTP request method.
         */
        static HttpMethod Parse(const std::string_view str, const HttpParserOptions& options);

        /**
         * Tries to parse an HTTP request method.
         * 
         * @param str A string containing an HTTP request method.
         * @returns If successful, an HttpMethod is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpMethod> TryParse(const std::string_view str);

        /**
         * Tries to parse an HTTP request method.
         * 
         * @param str A string containing an HTTP request method.
         * @param options Options for the HTTP parser.
         * @returns If successful, an HttpMethod is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpMethod> TryParse(const std::string_view str, const HttpParserOptions& options);

        /**
         * 
         * 
         * @returns true if the provided method is a standard method; otherwise, false.
         */
        static bool IsStandardRequestMethod(const HttpMethod& method);

    };

}

#endif // _VNETHTTP_HTTP_HTTPMETHOD_H_