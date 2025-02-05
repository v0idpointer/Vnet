/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef VNET_BUILD_VNETHTTP
#define VNET_BUILD_VNETHTTP
#endif

#include <Vnet/Http/HttpMethod.h>

using namespace Vnet::Http;

const HttpMethod HttpMethod::GET = { "GET" };
const HttpMethod HttpMethod::HEAD = { "HEAD" };
const HttpMethod HttpMethod::POST = { "POST" };
const HttpMethod HttpMethod::PUT = { "PUT" };
const HttpMethod HttpMethod::DELETE = { "DELETE" };
const HttpMethod HttpMethod::CONNECT = { "CONNECT" };
const HttpMethod HttpMethod::OPTIONS = { "OPTIONS" };
const HttpMethod HttpMethod::TRACE = { "TRACE" };
const HttpMethod HttpMethod::PATCH = { "PATCH" };

HttpMethod::HttpMethod(const std::string_view name) {
    this->m_name = name;
}

HttpMethod::HttpMethod(const HttpMethod& method) {
    this->operator= (method);
}

HttpMethod::HttpMethod(HttpMethod&& method) noexcept {
    this->operator= (std::move(method));
}

HttpMethod::~HttpMethod() { }

HttpMethod& HttpMethod::operator= (const HttpMethod& method) {
    if (this != &method) this->m_name = method.m_name;
    return static_cast<HttpMethod&>(*this);
}

HttpMethod& HttpMethod::operator= (HttpMethod&& method) noexcept {
    if (this != &method) this->m_name = std::move(method.m_name);
    return static_cast<HttpMethod&>(*this);
}

bool HttpMethod::operator== (const HttpMethod& method) const {
    return (this->m_name == method.m_name);
}

const std::string& HttpMethod::GetName() const {
    return this->m_name;
}

std::string HttpMethod::ToString() const {
    return this->GetName();
}