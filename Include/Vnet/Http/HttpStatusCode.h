/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPSTATUSCODE_H_
#define _VNETHTTP_HTTP_HTTPSTATUSCODE_H_

#include <Vnet/Exports.h>

#include <string>
#include <string_view>
#include <cstdint>
#include <optional>

namespace Vnet::Http {

    /**
     * Represents an HTTP response status code.
     */
    class VNETHTTPAPI HttpStatusCode {

    public:

                /* Informational responses */

        /** 100 Continue */
        static const HttpStatusCode CONTINUE;

        /** 101 Switching Protocols */
        static const HttpStatusCode SWITCHING_PROTOCOLS;

        /** 102 Processing */
        static const HttpStatusCode PROCESSING;

        /** 103 Early Hints */
        static const HttpStatusCode EARLY_HINTS;



                /* Successful responses */

        /** 200 OK */
        static const HttpStatusCode OK;

        /** 201 Created */
        static const HttpStatusCode CREATED;

        /** 202 Accepted */
        static const HttpStatusCode ACCEPTED;

        /** 203 Non-Authoritative Information */
        static const HttpStatusCode NON_AUTHORITATIVE_INFORMATION;

        /** 204 No Content */
        static const HttpStatusCode NO_CONTENT;

        /** 205 Reset Content */
        static const HttpStatusCode RESET_CONTENT;

        /** 206 Partial Content */
        static const HttpStatusCode PARTIAL_CONTENT;

        /** 207 Multi-Status */
        static const HttpStatusCode MULTI_STATUS;

        /** 208 Already Reported */
        static const HttpStatusCode ALREADY_REPORTED;

        /** 226 IM Used */
        static const HttpStatusCode IM_USED;



                /* Redirection messages */

        /** 300 Multiple Choices */
        static const HttpStatusCode MULTIPLE_CHOICES;

        /** 301 Moved Permanently */
        static const HttpStatusCode MOVED_PERMANENTLY;

        /** 302 Found */
        static const HttpStatusCode FOUND;

        /** 303 See Other */
        static const HttpStatusCode SEE_OTHER;

        /** 304 Not Modified */
        static const HttpStatusCode NOT_MODIFIED;

        /** 305 Use Proxy */
        static const HttpStatusCode USE_PROXY;

        /** 307 Temporary Redirect */
        static const HttpStatusCode TEMPORARY_REDIRECT;

        /** 308 Permanent Redirect */
        static const HttpStatusCode PERMANENT_REDIRECT;



                /* Client error responses */

        /** 400 Bad Request */
        static const HttpStatusCode BAD_REQUEST;

        /** 401 Unauthorized */
        static const HttpStatusCode UNAUTHORIZED;

        /** 402 Payment Required */
        static const HttpStatusCode PAYMENT_REQUIRED;

        /** 403 Forbidden */
        static const HttpStatusCode FORBIDDEN;

        /** 404 Not Found */
        static const HttpStatusCode NOT_FOUND;

        /** 405 Method Not Allowed */
        static const HttpStatusCode METHOD_NOT_ALLOWED;

        /** 406 Not Acceptable */
        static const HttpStatusCode NOT_ACCEPTABLE;

        /** 407 Proxy Authentication Required */
        static const HttpStatusCode PROXY_AUTHENTICATION_REQUIRED;

        /** 408 Request Timeout */
        static const HttpStatusCode REQUEST_TIMEOUT;

        /** 409 Conflict */
        static const HttpStatusCode CONFLICT;

        /** 410 Gone */
        static const HttpStatusCode GONE;

        /** 411 Length Required */
        static const HttpStatusCode LENGTH_REQUIRED;

        /** 412 Precondition Failed */
        static const HttpStatusCode PRECONDITION_FAILED;

        /** 413 Content Too Large */
        static const HttpStatusCode CONTENT_TOO_LARGE;

        /** 414 URI Too Long */
        static const HttpStatusCode URI_TOO_LONG;

        /** 415 Unsupported Media Type */
        static const HttpStatusCode UNSUPPORTED_MEDIA_TYPE;

        /** 416 Range Not Satisfiable */
        static const HttpStatusCode RANGE_NOT_SATISFIABLE;

        /** 417 Expectation Failed */
        static const HttpStatusCode EXPECTATION_FAILED;

        /** 418 I'm a teapot */
        static const HttpStatusCode IM_A_TEAPOT;

        /** 421 Misdirected Request */
        static const HttpStatusCode MISDIRECTED_REQUEST;

        /** 422 Unprocessable Content */
        static const HttpStatusCode UNPROCESSABLE_CONTENT;

        /** 423 Locked */
        static const HttpStatusCode LOCKED;

        /** 424 Failed Dependency */
        static const HttpStatusCode FAILED_DEPENDENCY;

        /** 425 Too Early */
        static const HttpStatusCode TOO_EARLY;

        /** 426 Upgrade Required */
        static const HttpStatusCode UPGRADE_REQUIRED;

        /** 428 Precondition Required */
        static const HttpStatusCode PRECONDITION_REQUIRED;

        /** 429 Too Many Requests */
        static const HttpStatusCode TOO_MANY_REQUESTS;

        /** 431 Request Header Fields Too Large */
        static const HttpStatusCode REQUEST_HEADER_FIELDS_TOO_LARGE;

        /** 451 Unavailable For Legal Reasons */
        static const HttpStatusCode UNAVAILABLE_FOR_LEGAL_REASONS;



                /* Server error responses */

        /** 500 Internal Server Error */
        static const HttpStatusCode INTERNAL_SERVER_ERROR;

        /** 501 Not Implemented */
        static const HttpStatusCode NOT_IMPLEMENTED;

        /** 502 Bad Gateway */
        static const HttpStatusCode BAD_GATEWAY;

        /** 503 Service Unavailable */
        static const HttpStatusCode SERVICE_UNAVAILABLE;

        /** 504 Gateway Timeout */
        static const HttpStatusCode GATEWAY_TIMEOUT;

        /** 505 HTTP Version Not Supported */
        static const HttpStatusCode HTTP_VERSION_NOT_SUPPORTED;

        /** 506 Variant Also Negotiates */
        static const HttpStatusCode VARIANT_ALSO_NEGOTIATES;

        /** 507 Insufficient Storage */
        static const HttpStatusCode INSUFFICIENT_STORAGE;

        /** 508 Loop Detected */
        static const HttpStatusCode LOOP_DETECTED;

        /** 510 Not Extended */
        static const HttpStatusCode NOT_EXTENDED;

        /** 511 Network Authentication Required */
        static const HttpStatusCode NETWORK_AUTHENTICATION_REQUIRED;



    private:
        std::int32_t m_code;
        std::string m_name;

    public:
        HttpStatusCode(const std::int32_t code, const std::string_view name);
        HttpStatusCode(const HttpStatusCode& statusCode);
        HttpStatusCode(HttpStatusCode&& statusCode) noexcept;
        virtual ~HttpStatusCode(void);

        HttpStatusCode& operator= (const HttpStatusCode& statusCode);
        HttpStatusCode& operator= (HttpStatusCode&& statusCode) noexcept;
        bool operator== (const HttpStatusCode& statusCode) const;

        /**
         * Returns the numerical status code.
         * 
         * @returns An integer.
         */
        const std::int32_t GetCode(void) const;

        /**
         * Returns the name of the status code.
         * 
         * @returns A string.
         */
        const std::string& GetName(void) const;

        /**
         * Returns the string representation of the HttpStatusCode object.
         * 
         * @returns A string.
         */
        std::string ToString(void) const;

    private:
        static std::optional<HttpStatusCode> ParseStatusCode(std::string_view str, const bool exceptions);

    public:

        /**
         * Parses an HTTP response status code.
         * 
         * @param str
         * @returns An HttpStatusCode.
         * @exception std::runtime_error - Bad HTTP status code.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         */
        static HttpStatusCode Parse(const std::string_view str);

        /**
         * Tries to parse an HTTP response status code.
         * 
         * @param str
         * @returns If successful, an HttpStatusCode is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<HttpStatusCode> TryParse(const std::string_view str);

    };

}

#endif // _VNETHTTP_HTTP_HTTPSTATUSCODE_H_