/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPCOOKIECOLLECTION_H_
#define _VNETHTTP_HTTP_HTTPCOOKIECOLLECTION_H_

#include <Vnet/Http/HttpCookie.h>

#include <unordered_set>
#include <unordered_map>

namespace Vnet::Http {

    struct CookieHash {

        inline std::size_t operator() (const HttpCookie& cookie) const noexcept {
            
            const std::size_t h1 = std::hash<std::string>{ } (cookie.GetName());
            const std::size_t h2 = cookie.GetDomain().has_value() ? std::hash<std::string>{ } (*cookie.GetDomain()) : 0;
            const std::size_t h3 = cookie.GetPath().has_value() ? std::hash<std::string>{ } (*cookie.GetPath()) : 0;

            return (h1 ^ (h2 << 1) ^ (h3 << 2));
        }

    };

    struct CookieEqual {

        inline bool operator() (const HttpCookie& lhs, const HttpCookie& rhs) const noexcept {
            return ((lhs.GetName() == rhs.GetName()) && (lhs.GetDomain() == rhs.GetDomain()) && (lhs.GetPath() == rhs.GetPath()));
        }

    };

    /**
     * Represents a collection of HTTP cookies.
     */
    class VNETHTTPAPI HttpCookieCollection {

    public:
        using CookieSet = std::unordered_set<HttpCookie, CookieHash, CookieEqual>;
        using CookieMap = std::unordered_map<HttpCookie, DateTime, CookieHash, CookieEqual>;

    private:
        CookieSet m_cookies;
        CookieMap m_dates;

    public:

        /**
         * Constructs a new HttpCookieCollection object.
         */
        HttpCookieCollection(void);

        /**
         * Constructs a new HttpCookieCollection object by copying an existing one.
         * 
         * @param cookies An HttpCookieCollection object to copy.
         */
        HttpCookieCollection(const HttpCookieCollection& cookies);
        
        HttpCookieCollection(HttpCookieCollection&& cookies) noexcept;
        virtual ~HttpCookieCollection(void);

        /**
         * Assigns the value from an existing HttpCookieCollection object to this object.
         * 
         * @param cookies An HttpCookieCollection object to copy.
         */
        HttpCookieCollection& operator= (const HttpCookieCollection& cookies);

        HttpCookieCollection& operator= (HttpCookieCollection&& cookies) noexcept;

        /**
         * Returns an iterator to the first HTTP cookie in the collection.
         */
        CookieSet::const_iterator begin(void) const;

        /**
         * Returns an iterator to the past-the-last HTTP cookie in the collection.
         */
        CookieSet::const_iterator end(void) const;

        /**
         * Returns an HTTP cookie from the collection.
         * 
         * @param name 
         * @param domain
         * @param path
         * @returns An HTTP cookie.
         * @exception std::out_of_range - The specified cookie does not exist.
         */
        const HttpCookie& Get(const std::string_view name, const std::optional<std::string_view> domain, const std::optional<std::string_view> path) const;

        /**
         * Returns an HTTP cookie from the collection.
         * 
         * @param name 
         * @returns An HTTP cookie.
         * @exception std::out_of_range - The specified cookie does not exist.
         */
        const HttpCookie& Get(const std::string_view name) const;

        /**
         * Checks if an HTTP cookie exists in the collection.
         * 
         * @param name
         * @param domain
         * @param path
         * @returns true if the collection contains a cookie with the specified name, domain and path; otherwise, false.
         */
        bool Contains(const std::string_view name, const std::optional<std::string_view> domain, const std::optional<std::string_view> path) const;

        /**
         * Checks if an HTTP cookie exists in the collection.
         * 
         * @param name
         * @returns true if the collection contains a cookie with the specified name; otherwise, false.
         */
        bool Contains(const std::string_view name) const;

        /**
         * Checks if an HTTP cookie exists in the collection.
         * 
         * @param cookie
         * @returns true if the collection contains the specified cookie; otherwise, false.
         */
        bool Contains(const HttpCookie& cookie) const;

        /**
         * Returns the number of HTTP cookies in the collection.
         * 
         * @returns An integer.
         */
        std::int32_t Count(void) const;

        /**
         * Adds an HTTP cookie to the collection.
         * 
         * @param cookie
         */
        void Add(const HttpCookie& cookie);

        /**
         * Removes an HTTP cookie from the collection.
         * 
         * @param cookie
         */
        void Remove(const HttpCookie& cookie);

        /**
         * Removes all session cookies and cookies that have expired.
         */
        void RemoveExpired(void);

        /**
         * Removes all HTTP cookies from the collection.
         */
        void Clear(void);

        /**
         * Returns the string representation of the HttpCookieCollection object.
         * 
         * @returns A string.
         */
        std::string ToString(void) const;

    private:
        static std::optional<HttpCookieCollection> ParseCookieCollection(const std::string_view str, const HttpParserOptions& options, const bool exceptions);
        
    public:

        /**
         * Parses a collection of HTTP cookies.
         * 
         * @param str A string containing HTTP cookies, separated by "; ".
         * @returns An HttpCookieCollection.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         * @exception HttpParserException - An error has occurred while parsing a collection of HTTP cookies.
         */
        static HttpCookieCollection Parse(const std::string_view str);
        
        /**
         * Parses a collection of HTTP cookies.
         * 
         * @param str A string containing HTTP cookies, separated by "; ".
         * @param options Options for the HTTP parser.
         * @returns An HttpCookieCollection.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         * @exception HttpParserException - An error has occurred while parsing a collection of HTTP cookies.
         */
        static HttpCookieCollection Parse(const std::string_view str, const HttpParserOptions& options);

        /**
         * Tries to parse a collection of HTTP cookies.
         * 
         * @param str A string containing HTTP cookies, separated by "; ".
         * @returns If successful, an HttpCookieCollection is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpCookieCollection> TryParse(const std::string_view str);
        
        /**
         * Tries to parse a collection of HTTP cookies.
         * 
         * @param str A string containing HTTP cookies, separated by "; ".
         * @param options Options for the HTTP parser.
         * @returns If successful, an HttpCookieCollection is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpCookieCollection> TryParse(const std::string_view str, const HttpParserOptions& options);

    };

}

#endif // _VNETHTTP_HTTP_HTTPCOOKIECOLLECTION_H_