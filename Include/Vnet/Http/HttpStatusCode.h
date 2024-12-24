/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPSTATUSCODE_H_
#define _VNETHTTP_HTTP_HTTPSTATUSCODE_H_

#include <Vnet/Exports.h>

#include <string>
#include <string_view>
#include <cstdint>
#include <optional>

namespace Vnet::Http {

    class VNETHTTPAPI HttpStatusCode {

    public:

        /* Informational responses */

        static const HttpStatusCode CONTINUE;
        static const HttpStatusCode SWITCHING_PROTOCOLS;
        static const HttpStatusCode PROCESSING;
        static const HttpStatusCode EARLY_HINTS;

        /* Successful responses */

        static const HttpStatusCode OK;
        static const HttpStatusCode CREATED;
        static const HttpStatusCode ACCEPTED;
        static const HttpStatusCode NON_AUTHORITATIVE_INFORMATION;
        static const HttpStatusCode NO_CONTENT;
        static const HttpStatusCode RESET_CONTENT;
        static const HttpStatusCode PARTIAL_CONTENT;
        static const HttpStatusCode MULTI_STATUS;
        static const HttpStatusCode ALREADY_REPORTED;
        static const HttpStatusCode IM_USED;

        /* Redirection messages */

        static const HttpStatusCode MULTIPLE_CHOICES;
        static const HttpStatusCode MOVED_PERMANENTLY;
        static const HttpStatusCode FOUND;
        static const HttpStatusCode SEE_OTHER;
        static const HttpStatusCode NOT_MODIFIED;
        static const HttpStatusCode USE_PROXY;
        static const HttpStatusCode TEMPORARY_REDIRECT;
        static const HttpStatusCode PERMANENT_REDIRECT;

        /* Client error responses */

        static const HttpStatusCode BAD_REQUEST;
        static const HttpStatusCode UNAUTHORIZED;
        static const HttpStatusCode PAYMENT_REQUIRED;
        static const HttpStatusCode FORBIDDEN;
        static const HttpStatusCode NOT_FOUND;
        static const HttpStatusCode METHOD_NOT_ALLOWED;
        static const HttpStatusCode NOT_ACCEPTABLE;
        static const HttpStatusCode PROXY_AUTHENTICATION_REQUIRED;
        static const HttpStatusCode REQUEST_TIMEOUT;
        static const HttpStatusCode CONFLICT;
        static const HttpStatusCode GONE;
        static const HttpStatusCode LENGTH_REQUIRED;
        static const HttpStatusCode PRECONDITION_FAILED;
        static const HttpStatusCode CONTENT_TOO_LARGE;
        static const HttpStatusCode URI_TOO_LONG;
        static const HttpStatusCode UNSUPPORTED_MEDIA_TYPE;
        static const HttpStatusCode RANGE_NOT_SATISFIABLE;
        static const HttpStatusCode EXPECTATION_FAILED;
        static const HttpStatusCode IM_A_TEAPOT;
        static const HttpStatusCode MISDIRECTED_REQUEST;
        static const HttpStatusCode UNPROCESSABLE_CONTENT;
        static const HttpStatusCode LOCKED;
        static const HttpStatusCode FAILED_DEPENDENCY;
        static const HttpStatusCode TOO_EARLY;
        static const HttpStatusCode UPGRADE_REQUIRED;
        static const HttpStatusCode PRECONDITION_REQUIRED;
        static const HttpStatusCode TOO_MANY_REQUESTS;
        static const HttpStatusCode REQUEST_HEADER_FIELDS_TOO_LARGE;
        static const HttpStatusCode UNAVAILABLE_FOR_LEGAL_REASONS;

        /* Server error responses */

        static const HttpStatusCode INTERNAL_SERVER_ERROR;
        static const HttpStatusCode NOT_IMPLEMENTED;
        static const HttpStatusCode BAD_GATEWAY;
        static const HttpStatusCode SERVICE_UNAVAILABLE;
        static const HttpStatusCode GATEWAY_TIMEOUT;
        static const HttpStatusCode HTTP_VERSION_NOT_SUPPORTED;
        static const HttpStatusCode VARIANT_ALSO_NEGOTIATES;
        static const HttpStatusCode INSUFFICIENT_STORAGE;
        static const HttpStatusCode LOOP_DETECTED;
        static const HttpStatusCode NOT_EXTENDED;
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

        const std::int32_t GetCode(void) const;
        const std::string& GetName(void) const;

        std::string ToString(void) const;

    private:
        static std::optional<HttpStatusCode> ParseStatusCode(std::string_view str, const bool exceptions);

    public:
        static HttpStatusCode Parse(const std::string_view str);
        static std::optional<HttpStatusCode> TryParse(const std::string_view str);

    };

}

#endif // _VNETHTTP_HTTP_HTTPSTATUSCODE_H_