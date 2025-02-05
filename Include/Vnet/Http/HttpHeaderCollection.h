/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPHEADERCOLLECTION_H_
#define _VNETHTTP_HTTP_HTTPHEADERCOLLECTION_H_

#include <Vnet/Exports.h>
#include <Vnet/Http/HttpHeader.h>

#include <list>
#include <cstdint>

namespace Vnet::Http {

    /**
     * Represents a collection of HTTP headers.
     */
    class VNETHTTPAPI HttpHeaderCollection {

    private:
        static const std::string_view SPECIAL_HEADERS[];

    private:
        std::list<HttpHeader> m_headers;

    public:

        /**
         * Constructs a new HttpHeaderCollection object.
         */
        HttpHeaderCollection(void);
        
        /**
         * Constructs a new HttpHeaderCollection object by copying an existing one.
         * 
         * @param headers An HttpHeaderCollection object to copy.
         */
        HttpHeaderCollection(const HttpHeaderCollection& headers);
        
        HttpHeaderCollection(HttpHeaderCollection&& headers) noexcept;
        virtual ~HttpHeaderCollection(void);

        /**
         * Assigns the value from an existing HttpHeaderCollection object to this object.
         * 
         * @param An HttpHeaderCollection object to copy.
         */
        HttpHeaderCollection& operator= (const HttpHeaderCollection& headers);
        
        HttpHeaderCollection& operator= (HttpHeaderCollection&& headers) noexcept;
        
        /**
         * Compares this HttpHeaderCollection object with another for equality.
         * 
         * @param headers An HttpHeaderCollection object to compare with.
         * @returns true if the HttpHeaderCollection objects are equal; otherwise, false.
         */
        bool operator== (const HttpHeaderCollection& headers) const;

        std::list<HttpHeader>::const_iterator begin(void) const;
        std::list<HttpHeader>::const_iterator end(void) const;

        /**
         * Returns an HTTP header from the collection.
         * 
         * @param name Header name.
         * @returns An HttpHeader.
         * @exception std::out_of_range - The specified header does not exist.
         */
        const HttpHeader& Get(const std::string_view name) const;

        /**
         * Returns an HTTP header from the collection.
         * 
         * @param name Header name.
         * @returns An HttpHeader.
         * @exception std::out_of_range - The specified header does not exist.
         */
        HttpHeader& Get(const std::string_view name);

        /**
         * Returns the number of HTTP headers in the collection.
         * 
         * @returns An integer.
         */
        std::int32_t Count(void) const;

        /**
         * Checks if a header exists in the collection.
         * 
         * @param name Header name.
         * @returns true if the collection contains a header with the specified name; otherwise, false.
         */
        bool Contains(const std::string_view name) const;

        /**
         * Checks if a header exists in the collection.
         * 
         * @param header An HTTP header.
         * @returns true if the collection contains a header with the same name and value as the 'header' parameter;
         * otherwise, false.
         */
        bool Contains(const HttpHeader& header) const;

    private:
        static bool IsSpecialHeader(const std::string_view name);
        void AppendHeaderValue(const std::string_view name, const std::string_view value);

    public:
        
        /**
         * Adds an HTTP header to the collection.
         * 
         * @param name Header name.
         * @param value Header value.
         * @param force If true, the collection will not attempt to append the header value
         * to an already existing HTTP header with the same name. This value is ignored for
         * a special set of HTTP headers (for example Set-Cookie).
         * @exception std::runtime_error - Append failed (internal error).
         * @exception std::invalid_argument - The 'name' parameter is an empty string,
         * or 'name' contains invalid character(s), or the 'value' parameter is an empty
         * string, or 'value' contains invalid character(s).
         */
        void Add(const std::string_view name, const std::string_view value, const bool force);
        
        /**
         * Adds an HTTP header to the collection.
         * 
         * @param name Header name.
         * @param value Header value.
         * @exception std::runtime_error - Append failed (internal error).
         * @exception std::invalid_argument - The 'name' parameter is an empty string,
         * or 'name' contains invalid character(s), or the 'value' parameter is an empty
         * string, or 'value' contains invalid character(s).
         */
        void Add(const std::string_view name, const std::string_view value);
        
        /**
         * Adds an HTTP header to the collection.
         * 
         * @param header An HTTP Header.
         * @param force If true, the collection will not attempt to append the header value
         * to an already existing HTTP header with the same name. This value is ignored for
         * a special set of HTTP headers (for example Set-Cookie).
         * @exception std::runtime_error - Append failed (internal error).
         */
        void Add(const HttpHeader& header, const bool force);

        /**
         * Adds an HTTP header to the collection.
         * 
         * @param header An HTTP Header.
         * @exception std::runtime_error - Append failed (internal error).
         */
        void Add(const HttpHeader& header);

        /**
         * Removes all HTTP headers with the same name as the new header,
         * then adds the new header.
         * 
         * @param name Header name.
         * @param value Header value.
         * @exception std::invalid_argument - The 'name' parameter is an empty string,
         * or 'name' contains invalid character(s), or the 'value' parameter is an empty
         * string, or 'value' contains invalid character(s).
         */
        void Set(const std::string_view name, const std::string_view value);
        
        /**
         * Removes all HTTP headers with the same name as the new header,
         * then adds the new header.
         * 
         * @param header An HTTP header.
         */
        void Set(const HttpHeader& header);

        /**
         * Removes all HTTP headers with the same name as the new header,
         * then adds the new header.
         * 
         * @param header An HTTP header.
         */
        void Set(HttpHeader&& header) noexcept;

        /**
         * Removes all HTTP headers from the collection.
         */
        void Clear(void);
        
        /**
         * Removes an HTTP header.
         * 
         * @param header An HTTP header.
         */
        void Remove(const HttpHeader& header);

        /**
         * Removes all HTTP headers with the specified name.
         * 
         * @param name Header name.
         */
        void Remove(const std::string_view name);

        /**
         * Returns the string representation of the HttpHeaderCollection object.
         * 
         * @returns A string.
         */
        std::string ToString(void) const;

    private:
        static std::optional<HttpHeaderCollection> ParseHeaders(std::string_view str, const bool exceptions);

    public:

        /**
         * Parses a collection of HTTP headers.
         * 
         * @param str
         * @returns An HttpHeaderCollection.
         * @exception std::runtime_error - One or more bad HTTP headers.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         */
        static HttpHeaderCollection Parse(const std::string_view str);

        /**
         * Tries to parse a collection of HTTP headers.
         * 
         * @param str
         * @returns If successful, an HttpHeaderCollection is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpHeaderCollection> TryParse(const std::string_view str);

    };

}

#endif // _VNETHTTP_HTTP_HTTPHEADERCOLLECTION_H_