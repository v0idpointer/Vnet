/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/Http/HttpResponse.h>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <exception>
#include <stdexcept>

using namespace Vnet::Http;

HttpResponse::HttpResponse() :
    m_statusCode(HttpStatusCode::OK),
    m_headers(HttpHeaderCollection()),
    m_payload(std::vector<std::uint8_t>()) { }

HttpResponse::HttpResponse(const HttpResponse& response) : m_statusCode(HttpStatusCode::OK) {
    this->operator= (response);
}

HttpResponse::HttpResponse(HttpResponse&& response) noexcept : m_statusCode(HttpStatusCode::OK) {
    this->operator= (std::move(response));
}

HttpResponse::~HttpResponse() { }

HttpResponse& HttpResponse::operator= (const HttpResponse& response) {

    if (this != &response) {
        this->m_statusCode = response.m_statusCode;
        this->m_headers = response.m_headers;
        this->m_payload = { response.m_payload.begin(), response.m_payload.end() };
    }

    return static_cast<HttpResponse&>(*this);
}

HttpResponse& HttpResponse::operator= (HttpResponse&& response) noexcept {

    if (this != &response) {
        this->m_statusCode = std::move(response.m_statusCode);
        this->m_headers = std::move(response.m_headers);
        this->m_payload = std::move(response.m_payload);
    }

    return static_cast<HttpResponse&>(*this);
}

bool HttpResponse::operator== (const HttpResponse& response) const {

    if (this->m_statusCode != response.m_statusCode) return false;
    if (this->m_headers != response.m_headers) return false;

    if (this->m_payload.size() != response.m_payload.size()) return false;

    return std::equal(
        this->m_payload.begin(), 
        this->m_payload.end(), 
        response.m_payload.begin(), 
        response.m_payload.end()
    );

}

const HttpStatusCode& HttpResponse::GetStatusCode() const {
    return this->m_statusCode;
}

const HttpHeaderCollection& HttpResponse::GetHeaders() const {
    return this->m_headers;
}

HttpHeaderCollection& HttpResponse::GetHeaders() {
    return this->m_headers;
}

std::span<const std::uint8_t> HttpResponse::GetPayload() const {
    return std::span<const std::uint8_t>(this->m_payload);
}

std::span<std::uint8_t> HttpResponse::GetPayload() {
    return std::span<std::uint8_t>(this->m_payload);
}

void HttpResponse::SetStatusCode(const HttpStatusCode& statusCode) {
    this->m_statusCode = statusCode;
}

void HttpResponse::SetStatusCode(HttpStatusCode&& statusCode) noexcept {
    this->m_statusCode = std::move(statusCode);
}

void HttpResponse::SetHeaders(const HttpHeaderCollection& headers) {
    this->m_headers = headers;
}

void HttpResponse::SetHeaders(HttpHeaderCollection&& headers) noexcept {
    this->m_headers = std::move(headers);
}

void HttpResponse::SetPayload(const std::span<const std::uint8_t> payload) {

    if (payload.empty())
        throw std::invalid_argument("Empty payload buffer.");

    if (payload.size() > this->m_payload.size())
        this->ResizePayload(payload.size());

    std::memcpy(this->m_payload.data(), payload.data(), payload.size());

}

void HttpResponse::SetPayload(std::vector<std::uint8_t>&& payload) noexcept {
    this->m_payload = std::move(payload);
    if (this->m_payload.empty()) this->m_headers.Remove("Content-Length");
    else this->m_headers.Set("Content-Length", std::to_string(this->m_payload.size()));
}

void HttpResponse::ResizePayload(const std::size_t size) {
    this->m_payload.resize(size);
    if (size == 0) this->m_headers.Remove("Content-Length");
    else this->m_headers.Set("Content-Length", std::to_string(size));
}

void HttpResponse::DeletePayload() {
    this->m_payload = { };
    this->m_headers.Remove("Content-Length");
}

std::vector<std::uint8_t> HttpResponse::Serialize() const {

    std::ostringstream stream;

    stream << "HTTP/1.1 ";
    stream << this->m_statusCode.ToString() << "\r\n";

    const std::string headers = this->m_headers.ToString();
    if (!headers.empty()) stream << headers << "\r\n";

    stream << "\r\n";

    for (const std::uint8_t byte : this->m_payload)
        stream << static_cast<char>(byte);

    std::vector<std::uint8_t> data(stream.view().size());
    std::memcpy(data.data(), stream.view().data(), stream.view().length());

    return data;
}

std::optional<HttpResponse> HttpResponse::ParseResponse(std::span<const std::uint8_t> data, const bool exceptions) {
    
    if (data.empty()) {
        if (exceptions) throw std::invalid_argument("Empty buffer.");
        return std::nullopt;
    }

    HttpResponse response;
    std::string_view str = { reinterpret_cast<const char*>(data.data()), data.size() };

    /* parse the first line of the response (version and status) */

    std::size_t lineEnd = str.find("\r\n");
    if (lineEnd == std::string_view::npos) {
        if (exceptions) throw std::runtime_error("Bad HTTP response.");
        return std::nullopt;
    }

    const std::size_t versionEnd = str.find(' ');
    if ((versionEnd == std::string_view::npos) || (versionEnd >= lineEnd)) {
        if (exceptions) throw std::runtime_error("Bad HTTP response.");
        return std::nullopt;
    }

    // check if the version is http 1.0 or 1.1:
    const std::string_view version = str.substr(0, versionEnd);
    if ((version != "HTTP/1.0") && (version != "HTTP/1.1")) {
        if (exceptions) throw std::runtime_error("Unsupported HTTP version.");
        return std::nullopt;
    }

    str = str.substr(versionEnd + 1);
    lineEnd -= 9; // strlen("HTTP/1.1") + 1

    // parse the status code:
    std::optional<HttpStatusCode> statusCode = HttpStatusCode::TryParse(str.substr(0, lineEnd));
    if (!statusCode.has_value()) {
        if (exceptions) throw std::runtime_error("Bad HTTP response.");
        return std::nullopt;
    }

    response.SetStatusCode(std::move(statusCode.value()));

    str = str.substr(lineEnd + 2);
    if (str.empty()) return response;

    /* parse http headers */

    const std::size_t headersEnd = str.find("\r\n\r\n");
    if (headersEnd != std::string_view::npos) {

        std::string_view headers = str.substr(0, headersEnd);
        str = str.substr(headersEnd + 4); // +4 for CR LF CR LF

        std::optional<HttpHeaderCollection> collection = HttpHeaderCollection::TryParse(headers);
        if (!collection.has_value()) {
            if (exceptions) throw std::runtime_error("Bad header(s) in HTTP response.");
            return std::nullopt;
        }

        response.SetHeaders(std::move(collection.value()));

    }

    if (str.empty()) return response;

    /* copy the payload */
   
    std::vector<std::uint8_t> payload(str.length());
    std::memcpy(payload.data(), str.data(), str.length());
    response.m_payload = std::move(payload);

    return response;
}

HttpResponse HttpResponse::Parse(const std::span<const std::uint8_t> data) {
    return HttpResponse::ParseResponse(data, true).value();
}

std::optional<HttpResponse> HttpResponse::TryParse(const std::span<const std::uint8_t> data) {
    return HttpResponse::ParseResponse(data, false);
}