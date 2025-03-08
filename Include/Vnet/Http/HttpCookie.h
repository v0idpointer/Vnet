/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPCOOKIE_H_
#define _VNETHTTP_HTTP_HTTPCOOKIE_H_

#include <Vnet/DateTime.h>
#include <Vnet/Http/SameSiteAttribute.h>
#include <Vnet/Http/HttpParserOptions.h>

namespace Vnet::Http {

    /**
     * Represents an HTTP cookie.
     */
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
        
        /**
         * Constructs a new HttpCookie object.
         * 
         * The name of the newly created cookie is "MyCookie",
         * and the value is an empty string.
         */
        HttpCookie(void);
        
        /**
         * Constructs a new HttpCookie object.
         * 
         * @param name Cookie name.
         * @param value Cookie value.
         * @exception std::invalid_argument - The 'name' parameter is an empty string,
         * or 'name' contains an invalid cookie name, or 'value' contains an invalid
         * cookie value.
         */
        HttpCookie(const std::string_view name, const std::string_view value);

        /**
         * Constructs a new HttpCookie object by copying an existing one.
         * 
         * @param cookie An HttpCookie object to copy.
         */
        HttpCookie(const HttpCookie& cookie);

        HttpCookie(HttpCookie&& cookie) noexcept;
        virtual ~HttpCookie(void);

        /**
         * Assigns the value from an existing HttpCookie object to this object.
         * 
         * @param cookie An HttpCookie object to copy.
         */
        HttpCookie& operator= (const HttpCookie& cookie);

        HttpCookie& operator= (HttpCookie&& cookie) noexcept;

        /**
         * Compares this HttpCookie object with another for equality.
         * 
         * @param cookie An HttpCookie object to compare with.
         * @returns true if the HttpCookie objects are equal; otherwise, false.
         */
        bool operator== (const HttpCookie& cookie) const;

        /**
         * Returns the cookie name.
         * 
         * @returns A string.
         */
        const std::string& GetName(void) const;

        /**
         * Returns the cookie value.
         * 
         * @returns A string.
         */
        const std::string& GetValue(void) const;

        /**
         * Returns the cookie's expiration date.
         * 
         * @returns An optional DateTime object.
         */
        const std::optional<DateTime> GetExpirationDate(void) const;

        /**
         * Returns the cookie's Time to Live (TTL).
         * 
         * @returns An optional integer.
         */
        const std::optional<std::int32_t> GetMaxAge(void) const;

        /**
         * Returns the cookie's domain scope.
         * 
         * The 'Domain' attribute specifies which server can receive a cookie.
         * 
         * @returns An optional string.
         */
        const std::optional<std::string>& GetDomain(void) const;

        /**
         * Returns the cookie's path scope.
         * 
         * The 'Path' attribute indicates a URI path that must exist in the requested
         * resource in order to send a cookie.
         * 
         * @returns An optional string.
         */
        const std::optional<std::string>& GetPath(void) const;

        /**
         * Checks if the 'Secure' attribute is set.
         * 
         * A cookie marked with the 'Secure' attribute is only sent
         * to the server over a secure connection (using HTTPS).
         * 
         * @returns An optional boolean.
         */
        const std::optional<bool> IsSecure(void) const;

        /**
         * Checks if the 'HttpOnly' attribute is set.
         * 
         * A cookie marked with the 'HttpOnly' attribute cannot
         * be accessed by JavaScript.
         * 
         * @returns An optional boolean.
         */
        const std::optional<bool> IsHttpOnly(void) const;

        /**
         * Returns the 'SameSite' attribute.
         * 
         * @returns A value from the SameSiteAttribute enum, or std::nullopt.
         */
        const std::optional<SameSiteAttribute> GetSameSite(void) const;

        /**
         * Sets the cookie name.
         * 
         * @param name Cookie name.
         * @exception std::invalid_argument - The 'name' parameter is an empty string,
         * or 'name' contains an invalid cookie name.
         */
        void SetName(const std::string_view name);

        /**
         * Sets the cookie value.
         * 
         * @param value Cookie value.
         * @exception std::invalid_argument - The 'value' parameter contains an
         * invalid cookie value.
         */
        void SetValue(const std::string_view value);

        /**
         * Sets the cookie's expiration date.
         * 
         * @param expirationDate A DateTime object.
         */
        void SetExpirationDate(const std::optional<DateTime> expirationDate);

        /**
         * Sets the cookie's Time to Live (TTL).
         * 
         * @param maxAge The time in seconds.
         */
        void SetMaxAge(const std::optional<std::int32_t> maxAge);

        /**
         * Sets the domain scope of the cookie.
         * 
         * The 'Domain' attribute specifies which server can receive a cookie.
         * 
         * @param domain
         */
        void SetDomain(const std::optional<std::string_view> domain);

        /**
         * Sets the path scope of the cookie.
         * 
         * The 'Path' attribute indicates a URI path that must exist in the requested
         * resource in order to send a cookie.
         * 
         * @param path
         */
        void SetPath(const std::optional<std::string_view> path);

        /**
         * Sets the 'Secure' attribute.
         * 
         * A cookie marked with the 'Secure' attribute is only sent
         * to the server over a secure connection (using HTTPS).
         * 
         * @param secure
         */
        void SetSecure(const std::optional<bool> secure);

        /**
         * Sets the 'HttpOnly' attribute.
         * 
         * A cookie marked with the 'HttpOnly' attribute cannot
         * be accessed by JavaScript.
         * 
         * @param httpOnly
         */
        void SetHttpOnly(const std::optional<bool> httpOnly);

        /**
         * Sets the 'SameSite' attribute.
         * 
         * @param sameSite A value from the SameSiteAttribute enum, or std::nullopt.
         * @exception std::invalid_argument - The 'sameSite' parameter contains an invalid value.
         */
        void SetSameSite(const std::optional<SameSiteAttribute> sameSite);

        /**
         * Returns the string representation of the HttpCookie object.
         * 
         * @returns A string.
         */
        std::string ToString(void) const;

    private:
        static bool IsValidValue(std::string_view);
        static std::string CharacterEscapeValue(std::string_view);
        static std::string CharacterUnescapeValue(std::string_view);
        static void ParseCookieAttribute(HttpCookie& cookie, std::string_view attrib, const HttpParserOptions& options);
        static std::optional<HttpCookie> ParseCookie(std::string_view str, const HttpParserOptions& options, const bool exceptions);

    public:

        /**
         * Parses an HTTP cookie.
         * 
         * @param str A string containing an HTTP cookie.
         * @returns An HttpCookie
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         * @exception HttpParserException - An error has occurred while parsing an HTTP cookie.
         */
        static HttpCookie Parse(const std::string_view str);

        /**
         * Parses an HTTP cookie.
         * 
         * @param str A string containing an HTTP cookie.
         * @param options Options for the HTTP parser.
         * @returns An HttpCookie
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         * @exception HttpParserException - An error has occurred while parsing an HTTP cookie.
         */
        static HttpCookie Parse(const std::string_view str, const HttpParserOptions& options);

        /**
         * Tries to parse an HTTP cookie.
         * 
         * @param str A string containing an HTTP cookie.
         * @returns If successful, an HttpCookie is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpCookie> TryParse(const std::string_view str);

        /**
         * Tries to parse an HTTP cookie.
         * 
         * @param str A string containing an HTTP cookie.
         * @param options Options for the HTTP parser.
         * @returns If successful, an HttpCookie is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpCookie> TryParse(const std::string_view str, const HttpParserOptions& options);

    };

}

#endif // _VNETHTTP_HTTP_HTTPCOOKIE_H_