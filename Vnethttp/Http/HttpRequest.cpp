/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Http/HttpRequest.h>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <exception>
#include <stdexcept>

using namespace Vnet;
using namespace Vnet::Http;

HttpRequest::HttpRequest() : 
    m_method(HttpMethod::GET), 
    m_uri(Uri()), 
    m_headers(HttpHeaderCollection()), 
    m_payload(std::vector<std::uint8_t>()) { }

HttpRequest::HttpRequest(const HttpRequest& request) : m_method(HttpMethod::GET) {
    this->operator= (request);
}

HttpRequest::HttpRequest(HttpRequest&& request) noexcept : m_method(HttpMethod::GET) {
    this->operator= (std::move(request));
}

HttpRequest::~HttpRequest() { }

HttpRequest& HttpRequest::operator= (const HttpRequest& request) {

    if (this != &request) {
        this->m_method = request.m_method;
        this->m_uri = request.m_uri;
        this->m_headers = request.m_headers;
        this->m_payload = { request.m_payload.begin(), request.m_payload.end() };
    }

    return static_cast<HttpRequest&>(*this);
}

HttpRequest& HttpRequest::operator= (HttpRequest&& request) noexcept {

    if (this != &request) {
        this->m_method = std::move(request.m_method);
        this->m_uri = std::move(request.m_uri);
        this->m_headers = std::move(request.m_headers);
        this->m_payload = std::move(request.m_payload);
    }

    return static_cast<HttpRequest&>(*this);
}

bool HttpRequest::operator== (const HttpRequest& request) const {

    if (this->m_method != request.m_method) return false;
    if (this->m_uri != request.m_uri) return false;
    if (this->m_headers != request.m_headers) return false;
    
    if (this->m_payload.size() != request.m_payload.size()) return false;

    return std::equal(
        this->m_payload.begin(), 
        this->m_payload.end(), 
        request.m_payload.begin(), 
        request.m_payload.end()
    );

}

const HttpMethod& HttpRequest::GetMethod() const {
    return this->m_method;
}

const Uri& HttpRequest::GetRequestUri() const {
    return this->m_uri;
}

const HttpHeaderCollection& HttpRequest::GetHeaders() const {
    return this->m_headers;
}

HttpHeaderCollection& HttpRequest::GetHeaders() {
    return this->m_headers;
}

std::span<const std::uint8_t> HttpRequest::GetPayload() const {
    return std::span<const std::uint8_t>(this->m_payload);
}

std::span<std::uint8_t> HttpRequest::GetPayload() {
    return std::span<std::uint8_t>(this->m_payload);
}

void HttpRequest::SetMethod(const HttpMethod& method) {
    this->m_method = method;
}

void HttpRequest::SetMethod(HttpMethod&& method) noexcept {
    this->m_method = std::move(method);
}

void HttpRequest::SetRequestUri(const Uri& uri) {
    this->m_uri = uri;
}

void HttpRequest::SetRequestUri(Uri&& uri) noexcept {
    this->m_uri = std::move(uri);
}

void HttpRequest::SetRequestUri(const std::string_view uri) {
    this->m_uri = Uri::Parse(uri);
}

void HttpRequest::SetHeaders(const HttpHeaderCollection& headers) {
    this->m_headers = headers;
}

void HttpRequest::SetHeaders(HttpHeaderCollection&& headers) noexcept {
    this->m_headers = std::move(headers);
}

void HttpRequest::SetPayload(const std::span<const std::uint8_t> payload) {
    
    if (payload.empty())
        throw std::invalid_argument("'payload': Empty buffer.");

    this->ResizePayload(payload.size());
    std::memcpy(this->m_payload.data(), payload.data(), payload.size());

}

void HttpRequest::SetPayload(std::vector<std::uint8_t>&& payload) noexcept {
    this->m_payload = std::move(payload);
    if (this->m_payload.empty()) this->m_headers.Remove("Content-Length");
    else this->m_headers.Set("Content-Length", std::to_string(this->m_payload.size()));
}

void HttpRequest::ResizePayload(const std::size_t size) {
    this->m_payload.resize(size);
    if (size == 0) this->m_headers.Remove("Content-Length");
    else this->m_headers.Set("Content-Length", std::to_string(size));
}

void HttpRequest::DeletePayload() {
    this->m_payload = { };
    this->m_headers.Remove("Content-Length");
}

std::vector<std::uint8_t> HttpRequest::Serialize() const {

    std::ostringstream stream;

    stream << this->m_method.ToString() << " ";

    stream << this->m_uri.GetPath().value_or("/");
    if (this->m_uri.GetQuery().has_value())
        stream << "?" << this->m_uri.GetQuery().value();
    if (this->m_uri.GetFragment().has_value())
        stream << "#" << this->m_uri.GetFragment().value();

    stream << " HTTP/1.1\r\n";
    
    const std::string headers = this->m_headers.ToString();
    if (!headers.empty()) stream << headers << "\r\n";

    stream << "\r\n";

    for (const std::uint8_t byte : this->m_payload)
        stream << static_cast<char>(byte);

    std::vector<std::uint8_t> data(stream.view().size());
    std::memcpy(data.data(), stream.view().data(), stream.view().length());

    return data;
}

std::optional<HttpRequest> HttpRequest::ParseRequest(std::span<const std::uint8_t> data, const bool exceptions) {

    if (data.empty()) {
        if (exceptions) throw std::invalid_argument("'data': Empty buffer.");
        return std::nullopt;
    }

    HttpRequest request;
    std::string_view str = { reinterpret_cast<const char*>(data.data()), data.size() };

    /* parse the first line of the request (method, uri and version) */

    std::size_t lineEnd = str.find("\r\n");
    if (lineEnd == std::string_view::npos) {
        if (exceptions) throw std::runtime_error("Bad HTTP request.");
        return std::nullopt;
    }

    // parse the method:
    const std::size_t methodEnd = str.find(' ');
    if ((methodEnd == std::string_view::npos) || (methodEnd >= lineEnd)) {
        if (exceptions) throw std::runtime_error("Bad HTTP request.");
        return std::nullopt;
    }

    HttpMethod method = { str.substr(0, methodEnd) };
    request.SetMethod(std::move(method));
    str = str.substr(methodEnd + 1);
    lineEnd -= (request.GetMethod().GetName().length() + 1);

    // parse the request uri:
    const std::size_t uriEnd = str.find(' ');
    if ((uriEnd == std::string_view::npos) || (uriEnd >= lineEnd)) {
        if (exceptions) throw std::runtime_error("Bad HTTP request.");
        return std::nullopt;
    }

    std::optional<Uri> uri = Uri::TryParse(str.substr(0, uriEnd));
    if (!uri.has_value()) {
        if (exceptions) throw std::runtime_error("Bad HTTP request.");
        return std::nullopt;
    }

    request.SetRequestUri(std::move(uri.value()));
    str = str.substr(uriEnd + 1);
    lineEnd -= (uriEnd + 1);

    // check if the version is http 1.0 or 1.1:
    const std::string_view version = str.substr(0, lineEnd);
    if ((version != "HTTP/1.0") && (version != "HTTP/1.1")) {
        if (exceptions) throw std::runtime_error("Unsupported HTTP version.");
        return std::nullopt;
    }

    str = str.substr(lineEnd + 2);
    if (str.empty()) return request;

    /* parse http headers */

    const std::size_t headersEnd = str.find("\r\n\r\n");
    if (headersEnd != std::string_view::npos) {

        std::string_view headers = str.substr(0, headersEnd);
        str = str.substr(headersEnd + 4); // +4 for CR LF CR LF

        std::optional<HttpHeaderCollection> collection = HttpHeaderCollection::TryParse(headers);
        if (!collection.has_value()) {
            if (exceptions) throw std::runtime_error("Bad header(s) in HTTP request.");
            return std::nullopt;
        }

        request.SetHeaders(std::move(collection.value()));

    }

    if (str.empty()) return request;

    /* copy the payload */

    std::vector<std::uint8_t> payload(str.length());
    std::memcpy(payload.data(), str.data(), str.length());
    request.m_payload = std::move(payload);

    return request;
}

HttpRequest HttpRequest::Parse(const std::span<const std::uint8_t> data) {
    return HttpRequest::ParseRequest(data, true).value();
}

std::optional<HttpRequest> HttpRequest::TryParse(const std::span<const std::uint8_t> data) {
    return HttpRequest::ParseRequest(data, false);
}