/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPPARSEROPTIONS_H_
#define _VNETHTTP_HTTP_HTTPPARSEROPTIONS_H_

#include <Vnet/Exports.h>

#include <cstdint>
#include <optional>

namespace Vnet::Http {

    /**
     * Represents a collection of options for the HTTP parser.
     */
    struct VNETHTTPAPI HttpParserOptions final {

        /**
         * The maximum length (in bytes) for an HTTP header name.
         * 
         * Default value: /
         * Used by: HttpHeader
         */
        std::optional<std::int32_t> MaxHeaderNameLength;
        
        /**
         * The maximum length (in bytes) for an HTTP header value.
         * 
         * Default value: /
         * Used by: HttpHeader
         */
        std::optional<std::int32_t> MaxHeaderValueLength;

        /**
         * The maximum number of headers an HTTP header collection can store.
         * 
         * Default value: /
         * Used by: HttpHeaderCollection
         */
        std::optional<std::int32_t> MaxHeaderCount;

        /**
         * 
         * 
         * Default value: true
         * Used by: HttpHeaderCollection
         */
        bool AppendHeadersWithIdenticalNames;

        /**
         * The maximum length (in bytes) for an HTTP request method.
         * 
         * Default value: /
         * Used by: HttpMethod
         */
        std::optional<std::int32_t> MaxRequestMethodLength;

        /**
         * Controls if non-standard (custom) HTTP request methods are allowed.
         * 
         * Default value: false
         * Used by: HttpRequest
         */
        bool AllowNonstandardRequestMethods;

        /**
         * The maximum length (in bytes) for a request URI.
         * 
         * Default value: /
         * Used by: HttpRequest
         */
        std::optional<std::int32_t> MaxRequestUriLength;

        /**
         * Controls if HTTP response status codes must be grouped into classes defined by RFC 9110.
         * 
         * Default value: true
         * Used by: HttpStatusCode
         */
        bool RestrictResponseStatusCodesToPredefinedClasses;

        /**
         * The maximum length (in bytes) for a response status code reason phrase.
         * 
         * Default value: /
         * Used by: HttpStatusCode
         */
        std::optional<std::int32_t> MaxResponseStatusCodeReasonPhraseLength;

        /**
         * Controls if non-standard (custom) HTTP response status codes are allowed.
         * 
         * Default: false
         * Used by: HttpResponse
         */
        bool AllowNonstandardResponseStatusCodes;

        /**
         * The maximum size (in bytes) for an HTTP message body.
         * 
         * Default value: /
         * Used by: HttpRequest and HttpResponse
         */
        std::optional<std::size_t> MaxPayloadSize;

        /**
         * 
         * 
         * Default value: false
         * Used by: HttpCookie
         */
        bool IgnoreNonstandardCookieAttributes;

        /**
         * 
         * 
         * Default value: false
         * Used by: HttpCookie
         */
        bool BypassIsValidCookieValueCheck;

        /**
         * 
         * 
         * Default value: false
         * Used by: HttpCookie
         */
        bool IgnoreMissingWhitespaceAfterCookieAttributeSeparator;

        /** Default HTTP parser options. */
        static const HttpParserOptions DEFAULT_OPTIONS;

        HttpParserOptions(void);
        HttpParserOptions(const HttpParserOptions& options);
        virtual ~HttpParserOptions(void);

        HttpParserOptions& operator= (const HttpParserOptions& options);

    };

}

#endif // _VNETHTTP_HTTP_HTTPPARSEROPTIONS_H_