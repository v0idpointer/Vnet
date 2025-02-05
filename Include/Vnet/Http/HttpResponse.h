/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPRESPONSE_H_
#define _VNETHTTP_HTTP_HTTPRESPONSE_H_

#include <Vnet/Http/HttpStatusCode.h>
#include <Vnet/Http/HttpHeaderCollection.h>

#include <cstdint>
#include <vector>
#include <span>

namespace Vnet::Http {

    /**
     * Represents an HTTP response.
     */
    class VNETHTTPAPI HttpResponse {

    private:
        HttpStatusCode m_statusCode;
        HttpHeaderCollection m_headers;
        std::vector<std::uint8_t> m_payload;

    public:

        /**
         * Constructs a new HttpResponse object.
         */
        HttpResponse(void);
        
        /**
         * Constructs a new HttpResponse object by copying an existing one.
         * 
         * @param response An HttpResponse object to copy.
         */
        HttpResponse(const HttpResponse& response);
        
        HttpResponse(HttpResponse&& response) noexcept;
        virtual ~HttpResponse(void);

        /**
         * Assigns the value from an existing HttpResponse object to this object.
         * 
         * @param response An HttpResponse object to copy.
         */
        HttpResponse& operator= (const HttpResponse& response);
        
        HttpResponse& operator= (HttpResponse&& response) noexcept;
        
        /**
         * Compares this HttpResponse object with another for equality.
         * 
         * @param response An HttpResponse object to compare with.
         * @returns true if the HttpResponse objects are equal; otherwise, false.
         */
        bool operator== (const HttpResponse& response) const;

        /**
         * Returns the response status code.
         * 
         * @returns An HttpStatusCode.
         */
        const HttpStatusCode& GetStatusCode(void) const;

        /**
         * Returns the collection of response headers.
         * 
         * @returns An HttpHeaderCollection.
         */
        const HttpHeaderCollection& GetHeaders(void) const;

        /**
         * Returns the collection of response headers.
         * 
         * @returns An HttpHeaderCollection.
         */
        HttpHeaderCollection& GetHeaders(void);

        /**
         * Returns the message body.
         * 
         * @returns A non-owning view into the message body.
         */
        std::span<const std::uint8_t> GetPayload(void) const;

        /**
         * Returns the message body.
         * 
         * @returns A non-owning view into the message body.
         */
        std::span<std::uint8_t> GetPayload(void);

        /**
         * Sets the response status code.
         * 
         * @param statusCode An HttpStatusCode.
         */
        void SetStatusCode(const HttpStatusCode& statusCode);

        /**
         * Sets the response status code.
         * 
         * @param statusCode An HttpStatusCode.
         */
        void SetStatusCode(HttpStatusCode&& statusCode) noexcept;

        /**
         * Sets the collection of response headers.
         * 
         * @param headers An HttpHeaderCollection.
         */
        void SetHeaders(const HttpHeaderCollection& headers);
        
        /**
         * Sets the collection of response headers.
         * 
         * @param headers An HttpHeaderCollection.
         */
        void SetHeaders(HttpHeaderCollection&& headers) noexcept;

        /**
         * Sets the message body.
         * 
         * This function will set the Content-Length header to the size of the new message body.
         * 
         * @param payload The new message body.
         * @exception std::invalid_argument - The 'payload' parameter is an empty buffer.
         */
        void SetPayload(const std::span<const std::uint8_t> payload);

        /**
         * Sets the message body.
         * 
         * If the new message body is not empty, this function will set
         * the Content-Length header to the size of the new message body;
         * otherwise, if the new message body is empty, this function will
         * remove the Content-Length header.
         * 
         * @param payload The new message body.
         */
        void SetPayload(std::vector<std::uint8_t>&& payload) noexcept;

        /**
         * Resizes the message body.
         * 
         * This function will set the Content-Length header to the new size
         * of the message body. If the new size is zero, meaning the response
         * does not have a message body, this function will remove the
         * Content-Length header.
         * 
         * @param size The new size of the payload.
         */
        void ResizePayload(const std::size_t size);

        /**
         * Removes the message body.
         * 
         * This function will remove the Content-Length header.
         */
        void DeletePayload(void);

        /**
         * Serializes the HttpResponse object.
         * 
         * @returns A vector of bytes.
         */
        std::vector<std::uint8_t> Serialize(void) const;

    private:
        static std::optional<HttpResponse> ParseResponse(std::span<const std::uint8_t> data, const bool exceptions);

    public:

        /**
         * Parses an HTTP response message.
         * 
         * @param data A data buffer containing a serialized HttpResponse object.
         * @returns An HttpResponse.
         * @exception std::runtime_error - Bad HTTP response, or unsupported HTTP version,
         * or one or more bad HTTP headers.
         * @exception std::invalid_argument - The 'data' parameter is an empty buffer.
         */
        static HttpResponse Parse(const std::span<const std::uint8_t> data);

        /**
         * Tries to parse an HTTP response message.
         * 
         * @param data A data buffer containing a serialized HttpResponse object.
         * @returns If successful, an HttpResponse is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpResponse> TryParse(const std::span<const std::uint8_t> data);

    };

}

#endif // _VNETHTTP_HTTP_HTTPRESPONSE_H_