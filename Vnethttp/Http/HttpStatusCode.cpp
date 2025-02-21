/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef VNET_BUILD_VNETHTTP
#define VNET_BUILD_VNETHTTP
#endif

#include <Vnet/Http/HttpStatusCode.h>
#include <Vnet/Http/HttpParserException.h>

#include <sstream>
#include <algorithm>

using namespace Vnet::Http;

const HttpStatusCode HttpStatusCode::CONTINUE = { 100, "Continue" };
const HttpStatusCode HttpStatusCode::SWITCHING_PROTOCOLS = { 101, "Switching Protocols" };
const HttpStatusCode HttpStatusCode::PROCESSING = { 102, "Processing" };
const HttpStatusCode HttpStatusCode::EARLY_HINTS = { 103, "Early Hints" };

const HttpStatusCode HttpStatusCode::OK = { 200, "OK" };
const HttpStatusCode HttpStatusCode::CREATED = { 201, "Created" };
const HttpStatusCode HttpStatusCode::ACCEPTED = { 202, "Accepted" };
const HttpStatusCode HttpStatusCode::NON_AUTHORITATIVE_INFORMATION = { 203, "Non-Authoritative Information" };
const HttpStatusCode HttpStatusCode::NO_CONTENT = { 204, "No Content" };
const HttpStatusCode HttpStatusCode::RESET_CONTENT = { 205, "Reset Content" };
const HttpStatusCode HttpStatusCode::PARTIAL_CONTENT = { 206, "Partial Content" };
const HttpStatusCode HttpStatusCode::MULTI_STATUS = { 207, "Multi-Status" };
const HttpStatusCode HttpStatusCode::ALREADY_REPORTED = { 208, "Already Reported" };
const HttpStatusCode HttpStatusCode::IM_USED = { 226, "IM Used" };

const HttpStatusCode HttpStatusCode::MULTIPLE_CHOICES = { 300, "Multiple Choices" };
const HttpStatusCode HttpStatusCode::MOVED_PERMANENTLY = { 301, "Moved Permanently" };
const HttpStatusCode HttpStatusCode::FOUND = { 302, "Found" };
const HttpStatusCode HttpStatusCode::SEE_OTHER = { 303, "See Other" };
const HttpStatusCode HttpStatusCode::NOT_MODIFIED = { 304, "Not Modified" };
const HttpStatusCode HttpStatusCode::USE_PROXY = { 305, "Use Proxy" };
const HttpStatusCode HttpStatusCode::TEMPORARY_REDIRECT = { 307, "Temporary Redirect" };
const HttpStatusCode HttpStatusCode::PERMANENT_REDIRECT = { 308, "Permanent Redirect" };

const HttpStatusCode HttpStatusCode::BAD_REQUEST = { 400, "Bad Request" };
const HttpStatusCode HttpStatusCode::UNAUTHORIZED = { 401, "Unauthorized" };
const HttpStatusCode HttpStatusCode::PAYMENT_REQUIRED = { 402, "Payment Required" };
const HttpStatusCode HttpStatusCode::FORBIDDEN = { 403, "Forbidden" };
const HttpStatusCode HttpStatusCode::NOT_FOUND = { 404, "Not Found" };
const HttpStatusCode HttpStatusCode::METHOD_NOT_ALLOWED = { 405, "Method Not Allowed" };
const HttpStatusCode HttpStatusCode::NOT_ACCEPTABLE = { 406, "Not Acceptable" };
const HttpStatusCode HttpStatusCode::PROXY_AUTHENTICATION_REQUIRED = { 407, "Proxy Authentication Required" };
const HttpStatusCode HttpStatusCode::REQUEST_TIMEOUT = { 408, "Request Timeout" };
const HttpStatusCode HttpStatusCode::CONFLICT = { 409, "Conflict" };
const HttpStatusCode HttpStatusCode::GONE = { 410, "Gone" };
const HttpStatusCode HttpStatusCode::LENGTH_REQUIRED = { 411, "Length Required" };
const HttpStatusCode HttpStatusCode::PRECONDITION_FAILED = { 412, "Precondition Failed" };
const HttpStatusCode HttpStatusCode::CONTENT_TOO_LARGE = { 413, "Content Too Large" };
const HttpStatusCode HttpStatusCode::URI_TOO_LONG = { 414, "URI Too Long" };
const HttpStatusCode HttpStatusCode::UNSUPPORTED_MEDIA_TYPE = { 415, "Unsupported Media Type" };
const HttpStatusCode HttpStatusCode::RANGE_NOT_SATISFIABLE = { 416, "Range Not Satisfiable" };
const HttpStatusCode HttpStatusCode::EXPECTATION_FAILED = { 417, "Expectation Failed" };
const HttpStatusCode HttpStatusCode::IM_A_TEAPOT = { 418, "I'm a teapot" };
const HttpStatusCode HttpStatusCode::MISDIRECTED_REQUEST = { 421, "Misdirected Request" };
const HttpStatusCode HttpStatusCode::UNPROCESSABLE_CONTENT = { 422, "Unprocessable Content" };
const HttpStatusCode HttpStatusCode::LOCKED = { 423, "Locked" };
const HttpStatusCode HttpStatusCode::FAILED_DEPENDENCY = { 424, "Failed Dependency" };
const HttpStatusCode HttpStatusCode::TOO_EARLY = { 425, "Too Early" };
const HttpStatusCode HttpStatusCode::UPGRADE_REQUIRED = { 426, "Upgrade Required" };
const HttpStatusCode HttpStatusCode::PRECONDITION_REQUIRED = { 428, "Precondition Required" };
const HttpStatusCode HttpStatusCode::TOO_MANY_REQUESTS = { 429, "Too Many Requests" };
const HttpStatusCode HttpStatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE = { 431, "Request Header Fields Too Large" };
const HttpStatusCode HttpStatusCode::UNAVAILABLE_FOR_LEGAL_REASONS = { 451, "Unavailable For Legal Reasons" };

const HttpStatusCode HttpStatusCode::INTERNAL_SERVER_ERROR = { 500, "Internal Server Error" };
const HttpStatusCode HttpStatusCode::NOT_IMPLEMENTED = { 501, "Not Implemented" };
const HttpStatusCode HttpStatusCode::BAD_GATEWAY = { 502, "Bad Gateway" };
const HttpStatusCode HttpStatusCode::SERVICE_UNAVAILABLE = { 503, "Service Unavailable" };
const HttpStatusCode HttpStatusCode::GATEWAY_TIMEOUT = { 504, "Gateway Timeout" };
const HttpStatusCode HttpStatusCode::HTTP_VERSION_NOT_SUPPORTED = { 505, "HTTP Version Not Supported" };
const HttpStatusCode HttpStatusCode::VARIANT_ALSO_NEGOTIATES = { 506, "Variant Also Negotiates" };
const HttpStatusCode HttpStatusCode::INSUFFICIENT_STORAGE = { 507, "Insufficient Storage" };
const HttpStatusCode HttpStatusCode::LOOP_DETECTED = { 508, "Loop Detected" };
const HttpStatusCode HttpStatusCode::NOT_EXTENDED = { 510, "Not Extended" };
const HttpStatusCode HttpStatusCode::NETWORK_AUTHENTICATION_REQUIRED = { 511, "Network Authentication Required" };

HttpStatusCode::HttpStatusCode(const std::int32_t code, const std::string_view reasonPhrase) {
    this->SetCode(code);
    this->SetReasonPhrase(reasonPhrase);
}

HttpStatusCode::HttpStatusCode(const HttpStatusCode& statusCode) {
    this->operator= (statusCode);
}

HttpStatusCode::HttpStatusCode(HttpStatusCode&& statusCode) noexcept {
    this->operator= (std::move(statusCode));
}

HttpStatusCode::~HttpStatusCode() { }

HttpStatusCode& HttpStatusCode::operator= (const HttpStatusCode& statusCode) {

    if (this != &statusCode) {
        this->m_code = statusCode.m_code;
        this->m_reasonPhrase = statusCode.m_reasonPhrase;
    }

    return static_cast<HttpStatusCode&>(*this);
}

HttpStatusCode& HttpStatusCode::operator= (HttpStatusCode&& statusCode) noexcept {

    if (this != &statusCode) {
        this->m_code = statusCode.m_code;
        this->m_reasonPhrase = std::move(statusCode.m_reasonPhrase);
    }

    return static_cast<HttpStatusCode&>(*this);
}

bool HttpStatusCode::operator== (const HttpStatusCode& statusCode) const {
    if (this->m_code != statusCode.m_code) return false;
    if (this->m_reasonPhrase != statusCode.m_reasonPhrase) return false;
    return true;
}

const std::int32_t HttpStatusCode::GetCode() const {
    return this->m_code;
}

const std::string& HttpStatusCode::GetReasonPhrase() const {
    return this->m_reasonPhrase;
}

void HttpStatusCode::SetCode(const std::int32_t code) {

    if (code < 0)
        throw std::invalid_argument("'code': Invalid numerical status code.");

    this->m_code = code;

}

void HttpStatusCode::SetReasonPhrase(const std::string_view reasonPhrase) {

    if (reasonPhrase.empty())
        throw std::invalid_argument("'reasonPhrase': Empty string.");

    std::string_view::const_iterator it;
    it = std::find_if(reasonPhrase.begin(), reasonPhrase.end(), [] (const char ch) -> bool {
        if ((ch >= 0x20) && (ch < 0x7F)) return false;
        else return true;
    });

    if (it != reasonPhrase.end())
        throw std::invalid_argument("'reasonPhrase': Invalid reason phrase.");

    this->m_reasonPhrase = reasonPhrase;

}

std::string HttpStatusCode::ToString() const {
    std::ostringstream stream;
    stream << this->GetCode() << " " << this->GetReasonPhrase();
    return stream.str();
}

std::optional<HttpStatusCode> HttpStatusCode::ParseStatusCode(std::string_view str, const HttpParserOptions& options, const bool exceptions) {

    if (str.empty()) {
        if (exceptions) throw std::invalid_argument("'str': Empty string.");
        return std::nullopt;
    }

    std::size_t pos = 0;
    if ((pos = str.find(' ')) == std::string_view::npos) {
        
        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad response status code.", 
            std::nullopt
        );
        
        return std::nullopt;
    }

    std::int32_t code = 0;
    try { code = std::stoi(std::string(str.substr(0, pos))); }
    catch (const std::invalid_argument& ex) {
        
        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad response status code: invalid value.", 
            std::nullopt
        );
        
        return std::nullopt;
    }
    catch (const std::out_of_range& ex) {
        
        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad response status code: value out of range.", 
            std::nullopt
        );
        
        return std::nullopt;
    }

    if (options.RestrictResponseStatusCodesToPredefinedClasses && ((code < 100) || (code >= 600))) {

        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad response status code: value out of range.", 
            std::nullopt
        );

        return std::nullopt;
    }

    const std::string_view text = str.substr(pos + 1);
    if (options.MaxResponseStatusCodeReasonPhraseLength && (text.length() > *options.MaxResponseStatusCodeReasonPhraseLength)) {

        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad response status code: reason phrase too long.", 
            std::nullopt
        );

        return std::nullopt;
    }

    std::optional<HttpStatusCode> statusCode;
    try { statusCode = { code, text }; }
    catch (const std::invalid_argument& ex) {

        std::size_t pos = 0;
        std::string msg = ex.what();
        if ((pos = msg.find(": ")) != std::string::npos)
            msg = msg.substr(pos + 2);

        if (!msg.empty()) {
            char& ch = msg.front();
            if ((ch >= 'A') && (ch <= 'Z')) ch += ('a' - 'A');
        }

        if (exceptions) throw HttpParserException(
            ("HTTP parser error: bad response status code: " + msg),
            std::nullopt
        );

        return std::nullopt;
    }

    return statusCode.value();
}

HttpStatusCode HttpStatusCode::Parse(const std::string_view str) {
    return HttpStatusCode::Parse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

HttpStatusCode HttpStatusCode::Parse(const std::string_view str, const HttpParserOptions& options) {
    return HttpStatusCode::ParseStatusCode(str, options, true).value();
}

std::optional<HttpStatusCode> HttpStatusCode::TryParse(const std::string_view str) {
    return HttpStatusCode::TryParse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

std::optional<HttpStatusCode> HttpStatusCode::TryParse(const std::string_view str, const HttpParserOptions& options) {
    return HttpStatusCode::ParseStatusCode(str, options, false);
}

bool HttpStatusCode::IsStandardResponseCode(const HttpStatusCode& statusCode) {

    const std::int32_t code = statusCode.GetCode();

    // informational responses
    if ((code >= 100) && (code <= 103)) return true;

    // successful responses
    if ((code >= 200) && (code <= 208)) return true;
    if (code == 226) return true;

    // redirection messages:
    if ((code >= 300) && (code <= 305)) return true;
    if ((code == 307) || (code == 308)) return true;

    // client error responses:
    if ((code >= 400) && (code <= 418)) return true;
    if ((code >= 421) && (code <= 426)) return true;
    if ((code == 428) || (code == 429)) return true;
    if (code == 431) return true;
    if (code == 451) return true;

    // server error responses:
    if ((code >= 500) && (code <= 508)) return true;
    if ((code == 510) || (code == 511)) return true;

    return false;
}