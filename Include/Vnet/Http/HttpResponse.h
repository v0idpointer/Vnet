/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPRESPONSE_H_
#define _VNETHTTP_HTTP_HTTPRESPONSE_H_

#include <Vnet/Http/HttpStatusCode.h>
#include <Vnet/Http/HttpHeaderCollection.h>

#include <cstdint>
#include <vector>
#include <span>

namespace Vnet::Http {

    class VNETHTTPAPI HttpResponse {

    private:
        HttpStatusCode m_statusCode;
        HttpHeaderCollection m_headers;
        std::vector<std::uint8_t> m_payload;

    public:
        HttpResponse(void);
        HttpResponse(const HttpResponse& response);
        HttpResponse(HttpResponse&& response) noexcept;
        virtual ~HttpResponse(void);

        HttpResponse& operator= (const HttpResponse& response);
        HttpResponse& operator= (HttpResponse&& response) noexcept;
        bool operator== (const HttpResponse& response) const;

        const HttpStatusCode& GetStatusCode(void) const;
        const HttpHeaderCollection& GetHeaders(void) const;
        HttpHeaderCollection& GetHeaders(void);
        std::span<const std::uint8_t> GetPayload(void) const;
        std::span<std::uint8_t> GetPayload(void);

        void SetStatusCode(const HttpStatusCode& statusCode);
        void SetStatusCode(HttpStatusCode&& statusCode) noexcept;
        void SetHeaders(const HttpHeaderCollection& headers);
        void SetHeaders(HttpHeaderCollection&& headers) noexcept;
        void SetPayload(const std::span<const std::uint8_t> payload);
        void SetPayload(std::vector<std::uint8_t>&& headers) noexcept;
        void ResizePayload(const std::size_t size);
        void DeletePayload(void);

        std::vector<std::uint8_t> Serialize(void) const;

    private:
        static std::optional<HttpResponse> ParseResponse(std::span<const std::uint8_t> data, const bool exceptions);

    public:
        static HttpResponse Parse(const std::span<const std::uint8_t> data);
        static std::optional<HttpResponse> TryParse(const std::span<const std::uint8_t> data);

    };

}

#endif // _VNETHTTP_HTTP_HTTPRESPONSE_H_