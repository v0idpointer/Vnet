/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPHEADERCOLLECTION_H_
#define _VNETHTTP_HTTP_HTTPHEADERCOLLECTION_H_

#include <Vnet/Exports.h>
#include <Vnet/Http/HttpHeader.h>

#include <list>
#include <cstdint>

namespace Vnet::Http {

    class VNETHTTPAPI HttpHeaderCollection {

    private:
        static const std::string_view SPECIAL_HEADERS[];

    private:
        std::list<HttpHeader> m_headers;

    public:
        HttpHeaderCollection(void);
        HttpHeaderCollection(const HttpHeaderCollection& headers);
        HttpHeaderCollection(HttpHeaderCollection&& headers) noexcept;
        virtual ~HttpHeaderCollection(void);

        HttpHeaderCollection& operator= (const HttpHeaderCollection& headers);
        HttpHeaderCollection& operator= (HttpHeaderCollection&& headers) noexcept;
        bool operator== (const HttpHeaderCollection& headers) const;

        std::list<HttpHeader>::const_iterator begin(void) const;
        std::list<HttpHeader>::const_iterator end(void) const;

        const HttpHeader& Get(const std::string_view name) const;
        HttpHeader& Get(const std::string_view name);

        std::int32_t Count(void) const;
        bool Contains(const std::string_view name) const;
        bool Contains(const HttpHeader& header) const;

    private:
        static bool IsSpecialHeader(const std::string_view name);
        void AppendHeaderValue(const std::string_view name, const std::string_view value);

    public:
        void Add(const std::string_view name, const std::string_view value, const bool force);
        void Add(const std::string_view name, const std::string_view value);
        void Add(const HttpHeader& header, const bool force);
        void Add(const HttpHeader& header);

        void Set(const std::string_view name, const std::string_view value);
        void Set(const HttpHeader& header);
        void Set(HttpHeader&& header) noexcept;

        void Clear(void);
        void Remove(const HttpHeader& header);
        void Remove(const std::string_view name);

        std::string ToString(void) const;

    private:
        static std::optional<HttpHeaderCollection> ParseHeaders(std::string_view str, const bool exceptions);

    public:
        static HttpHeaderCollection Parse(const std::string_view str);
        static std::optional<HttpHeaderCollection> TryParse(const std::string_view str);

    };

}

#endif // _VNETHTTP_HTTP_HTTPHEADERCOLLECTION_H_