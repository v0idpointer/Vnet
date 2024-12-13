/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef VNET_BUILD_VNETHTTP
#define VNET_BUILD_VNETHTTP
#endif

#include <Vnet/Http/HttpStatusCode.h>

#include <sstream>

using namespace Vnet::Http;

// https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
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

HttpStatusCode::HttpStatusCode(const std::int32_t code, const std::string_view name) {
    this->m_code = code;
    this->m_name = name;
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
        this->m_name = statusCode.m_name;
    }

    return static_cast<HttpStatusCode&>(*this);
}

HttpStatusCode& HttpStatusCode::operator= (HttpStatusCode&& statusCode) noexcept {

    if (this != &statusCode) {
        this->m_code = statusCode.m_code;
        this->m_name = std::move(statusCode.m_name);
    }

    return static_cast<HttpStatusCode&>(*this);
}

bool HttpStatusCode::operator== (const HttpStatusCode& statusCode) const {
    if (this->m_code != statusCode.m_code) return false;
    if (this->m_name != statusCode.m_name) return false;
    return true;
}

const std::int32_t HttpStatusCode::GetCode() const {
    return this->m_code;
}

const std::string& HttpStatusCode::GetName() const {
    return this->m_name;
}

std::string HttpStatusCode::ToString() const {
    std::ostringstream stream;
    stream << this->GetCode() << " " << this->GetName();
    return stream.str();
}