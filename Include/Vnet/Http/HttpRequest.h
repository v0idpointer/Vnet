/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
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

    /**
     * Represents an HTTP request.
     */
    class VNETHTTPAPI HttpRequest {

    private:
        HttpMethod m_method;
        Uri m_uri;
        HttpHeaderCollection m_headers;
        std::vector<std::uint8_t> m_payload;

    public:

        /**
         * Constructs a new HttpRequest object.
         */
        HttpRequest(void);
        
        /**
         * Constructs a new HttpRequest object by copying an existing one.
         * 
         * @param request An HttpRequest object to copy.
         */
        HttpRequest(const HttpRequest& request);
        
        HttpRequest(HttpRequest&& request) noexcept;
        virtual ~HttpRequest(void);

        /**
         * Assigns the value from an existing HttpRequest object to this object.
         * 
         * @param request An HttpRequest object to copy.
         */
        HttpRequest& operator= (const HttpRequest& request);
        
        HttpRequest& operator= (HttpRequest&& request) noexcept;
        
        /**
         * Compares this HttpRequest object with another for equality.
         * 
         * @param request An HttpRequest object to compare with.
         * @returns true if the HttpRequest objects are equal; otherwise, false.
         */
        bool operator== (const HttpRequest& request) const;

        /**
         * Returns the request method.
         * 
         * @returns An HttpMethod.
         */
        const HttpMethod& GetMethod(void) const;

        /**
         * Returns the request URI.
         * 
         * @returns A Uri.
         */
        const Uri& GetRequestUri(void) const;

        /**
         * Returns the collection of request headers.
         * 
         * @returns An HttpHeaderCollection.
         */
        const HttpHeaderCollection& GetHeaders(void) const;

        /**
         * Returns the collection of request headers.
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
         * Sets the request method.
         * 
         * @param method An HttpMethod.
         */
        void SetMethod(const HttpMethod& method);

        /**
         * Sets the request method.
         * 
         * @param method An HttpMethod.
         */
        void SetMethod(HttpMethod&& method) noexcept;

        /**
         * Sets the request URI.
         * 
         * @param uri A Uri.
         */
        void SetRequestUri(const Uri& uri);

        /**
         * Sets the request URI.
         * 
         * @param uri A Uri.
         */
        void SetRequestUri(Uri&& uri) noexcept;

        /**
         * Sets the request URI.
         * 
         * @param uri A string containing a URI.
         * @exception std::invalid_argument - The 'uri' parameter is an empty string.
         * @exception BadUriException - URI malformed.
         */
        void SetRequestUri(const std::string_view uri);

        /**
         * Sets the collection of request headers.
         * 
         * @param headers An HttpHeaderCollection.
         */
        void SetHeaders(const HttpHeaderCollection& headers);

        /**
         * Sets the collection of request headers.
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
         * of the message body. If the new size is zero, meaning the request
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
         * Serializes the HttpRequest object.
         * 
         * @return A vector of bytes.
         */
        std::vector<std::uint8_t> Serialize(void) const;

    private:
        static std::size_t ParseContentLength(const std::string_view str);
        static std::optional<HttpRequest> ParseRequest(std::span<const std::uint8_t> data, const HttpParserOptions& options, const bool exceptions);

    public:

        /**
         * Parses an HTTP request message.
         * 
         * @param data A data buffer containing a serialized HttpRequest object.
         * @returns An HttpRequest.
         * @exception std::invalid_argument - The 'data' parameter is an empty buffer.
         * @exception HttpParserException - An error has occurred while parsing an HTTP request.
         */
        static HttpRequest Parse(const std::span<const std::uint8_t> data);

        /**
         * Parses an HTTP request message.
         * 
         * @param data A data buffer containing a serialized HttpRequest object.
         * @param options Options for the HTTP parser.
         * @returns An HttpRequest.
         * @exception std::invalid_argument - The 'data' parameter is an empty buffer.
         * @exception HttpParserException - An error has occurred while parsing an HTTP request.
         */
        static HttpRequest Parse(const std::span<const std::uint8_t> data, const HttpParserOptions& options);

        /**
         * Tries to parse an HTTP request message.
         * 
         * @param data A data buffer containing a serialized HttpRequest object.
         * @returns If successful, an HttpRequest is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpRequest> TryParse(const std::span<const std::uint8_t> data);

        /**
         * Tries to parse an HTTP request message.
         * 
         * @param data A data buffer containing a serialized HttpRequest object.
         * @param options Options for the HTTP parser.
         * @returns If successful, an HttpRequest is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpRequest> TryParse(const std::span<const std::uint8_t> data, const HttpParserOptions& options);

    };

}

#endif // _VNETHTTP_HTTP_HTTPREQUEST_H_