/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETWEB_WEB_COOKIESTORAGE_H_
#define _VNETWEB_WEB_COOKIESTORAGE_H_

#include <Vnet/Uri.h>
#include <Vnet/Http/HttpCookieCollection.h>

#include <vector>

namespace Vnet::Web {

    /**
     * Represents a collection of per-domain HTTP cookie collections.
     */
    class VNETWEBAPI CookieStorage {

    private:
        std::unordered_map<std::string, Vnet::Http::HttpCookieCollection> m_collections;

    public:

        /**
         * Constructs a new CookieStorage object.
         */
        CookieStorage(void);

        /**
         * Constructs a new CookieStorage object by copying an existing one.
         * 
         * @param storage A CookieStorage object to copy.
         */
        CookieStorage(const CookieStorage& storage);

        CookieStorage(CookieStorage&& storage) noexcept;
        virtual ~CookieStorage(void);

        /**
         * Assigns the value from an existing CookieStorage object to this object.
         * 
         * @param storage A CookieStorage object to copy.
         */
        CookieStorage& operator= (const CookieStorage& storage);

        CookieStorage& operator= (CookieStorage&& storage) noexcept;

        /**
         * Returns an iterator to the first per-domain cookie collection.
         */
        std::unordered_map<std::string, Vnet::Http::HttpCookieCollection>::const_iterator begin(void) const;

        /**
         * Returns an iterator to the past-the-last per-domain cookie collection.
         */
        std::unordered_map<std::string, Vnet::Http::HttpCookieCollection>::const_iterator end(void) const;

    private:
        static std::vector<std::string> GetDomains(const Uri&);

    public:
        
        /**
         * Compiles a collection of HTTP cookies that should be included in an HTTP request.
         * 
         * @param requestUri
         * @returns A collection of HTTP cookies.
         * @exception std::invalid_argument - The 'requestUri' parameter contains a
         * relative URI, or the scheme component of 'requestUri' is an unsupported
         * scheme, or the host component of 'requestUri' is std::nullopt.
         */
        Vnet::Http::HttpCookieCollection GetCookies(const Uri& requestUri) const;

        /**
         * Adds an HTTP cookie to a per-domain collection.
         * 
         * @param requestUri 
         * @param cookie
         * @exception std::invalid_argument - The 'requestUri' parameter contains a
         * relative URI, or the scheme component of 'requestUri' is an unsupported
         * scheme, or the host component of 'requestUri' is std::nullopt.
         * @exception HttpException - Cookie rejected.
         */
        void AddCookie(const Uri& requestUri, Vnet::Http::HttpCookie cookie);

        /**
         * Removes an HTTP cookie from a per-domain collection.
         * 
         * @param requestUri
         * @param cookie
         * @exception std::invalid_argument - The 'requestUri' parameter contains a
         * relative URI, or the scheme component of 'requestUri' is an unsupported
         * scheme, or the host component of 'requestUri' is std::nullopt.
         */
        void RemoveCookie(const Uri& requestUri, const Vnet::Http::HttpCookie& cookie);

        /**
         * Removes all session cookies and cookies that have expired.
         */
        void RemoveExpiredCookies(void);

        /**
         * Removes all HTTP cookies from a per-domain collection.
         * 
         * @exception std::invalid_argument - The 'requestUri' parameter contains a
         * relative URI, or the scheme component of 'requestUri' is an unsupported
         * scheme, or the host component of 'requestUri' is std::nullopt.
         */
        void ClearCookies(const Uri& requestUri);

        /**
         * Removes all HTTP cookies from all per-domain collections.
         */
        void ClearCookies(void);

        /**
         * Exports all HTTP cookies in the Netscape HTTP cookie file format.
         * 
         * @returns A string.
         */
        std::string ToString(void) const;

    };

}

#endif // _VNETWEB_WEB_COOKIESTORAGE_H_