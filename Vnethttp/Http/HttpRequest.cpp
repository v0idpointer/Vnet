/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/Http/HttpRequest.h>

#include <algorithm>
#include <cstring>
#include <sstream>

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
    
    if (payload.size() > this->m_payload.size())
        this->ResizePayload(payload.size());

    std::memcpy(this->m_payload.data(), payload.data(), payload.size());

}

void HttpRequest::SetPayload(std::vector<std::uint8_t>&& payload) noexcept {
    this->m_payload = std::move(payload);
    this->m_headers.Set("Content-Length", std::to_string(this->m_payload.size()));
}

void HttpRequest::ResizePayload(const std::size_t size) {
    this->m_payload.resize(size);
    this->m_headers.Set("Content-Length", std::to_string(size));
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