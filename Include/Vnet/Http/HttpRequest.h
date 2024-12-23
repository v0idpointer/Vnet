/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPREQUEST_H_
#define _VNETHTTP_HTTP_HTTPREQUEST_H_

#include <Vnet/Uri.h>
#include <Vnet/Http/HttpMethod.h>
#include <Vnet/Http/HttpHeaderCollection.h>

#include <cstdint>
#include <vector>
#include <span>

namespace Vnet::Http {

    class VNETHTTPAPI HttpRequest {

    private:
        HttpMethod m_method;
        Uri m_uri;
        HttpHeaderCollection m_headers;
        std::vector<std::uint8_t> m_payload;

    public:
        HttpRequest(void);
        HttpRequest(const HttpRequest& request);
        HttpRequest(HttpRequest&& request) noexcept;
        virtual ~HttpRequest(void);

        HttpRequest& operator= (const HttpRequest& request);
        HttpRequest& operator= (HttpRequest&& request) noexcept;
        bool operator== (const HttpRequest& request) const;

        const HttpMethod& GetMethod(void) const;
        const Uri& GetRequestUri(void) const;
        const HttpHeaderCollection& GetHeaders(void) const;
        HttpHeaderCollection& GetHeaders(void);
        std::span<const std::uint8_t> GetPayload(void) const;
        std::span<std::uint8_t> GetPayload(void);

        void SetMethod(const HttpMethod& method);
        void SetMethod(HttpMethod&& method) noexcept;
        void SetRequestUri(const Uri& uri);
        void SetRequestUri(Uri&& uri) noexcept;
        void SetRequestUri(const std::string_view uri);
        void SetHeaders(const HttpHeaderCollection& headers);
        void SetHeaders(HttpHeaderCollection&& headers) noexcept;
        void SetPayload(const std::span<const std::uint8_t> payload);
        void SetPayload(std::vector<std::uint8_t>&& headers) noexcept;
        void ResizePayload(const std::size_t size);
        void DeletePayload(void);

        std::vector<std::uint8_t> Serialize(void) const;

    };

}

#endif // _VNETHTTP_HTTP_HTTPREQUEST_H_