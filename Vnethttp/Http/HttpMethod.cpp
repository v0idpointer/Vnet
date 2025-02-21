/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef VNET_BUILD_VNETHTTP
#define VNET_BUILD_VNETHTTP
#endif

#include <Vnet/Http/HttpMethod.h>
#include <Vnet/Http/HttpParserException.h>

#include <algorithm>
#include <unordered_set>

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
    this->SetName(name);
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

void HttpMethod::SetName(const std::string_view name) {

    if (name.empty())
        throw std::invalid_argument("'name': Empty string.");

    std::string_view::const_iterator it;
    it = std::find_if(name.begin(), name.end(), [] (const char ch) -> bool {
        
        const std::unordered_set<char> specialCharacters = {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~'
        };

        if ((ch >= 'A') && (ch <= 'Z')) return false;
        if ((ch >= 'a') && (ch <= 'z')) return false;
        if ((ch >= '0') && (ch <= '9')) return false;
        if (specialCharacters.contains(ch)) return false;

        return true;
    });

    if (it != name.end())
        throw std::invalid_argument("'name': Invalid request method name.");

    this->m_name = name;

}

std::string HttpMethod::ToString() const {
    return this->GetName();
}

std::optional<HttpMethod> HttpMethod::ParseMethod(const std::string_view str, const HttpParserOptions& options, const bool exceptions) {

    if (str.empty()) {
        if (exceptions) throw std::invalid_argument("'str': Empty string.");
        return std::nullopt;
    }

    if (options.MaxRequestMethodLength && (str.length() > *options.MaxRequestMethodLength)) {

        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad request method: method name too long.",
            HttpStatusCode::METHOD_NOT_ALLOWED
        );

        return std::nullopt;
    }

    std::optional<HttpMethod> method;
    try { method = { str }; }
    catch (const std::exception& ex) {

        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad request method: invalid method name.",
            HttpStatusCode::METHOD_NOT_ALLOWED
        );

        return std::nullopt;
    }

    return method.value();
}

HttpMethod HttpMethod::Parse(const std::string_view str) {
    return HttpMethod::Parse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

HttpMethod HttpMethod::Parse(const std::string_view str, const HttpParserOptions& options) {
    return HttpMethod::ParseMethod(str, options, true).value();
}

std::optional<HttpMethod> HttpMethod::TryParse(const std::string_view str) {
    return HttpMethod::TryParse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

std::optional<HttpMethod> HttpMethod::TryParse(const std::string_view str, const HttpParserOptions& options) {
    return HttpMethod::ParseMethod(str, options, false);   
}

bool HttpMethod::IsStandardRequestMethod(const HttpMethod& method) {
    
    static const std::unordered_set<std::string> standardMethods = {
        
        HttpMethod::GET.GetName(),
        HttpMethod::HEAD.GetName(),
        HttpMethod::POST.GetName(),
        HttpMethod::PUT.GetName(),
        HttpMethod::DELETE.GetName(),
        HttpMethod::CONNECT.GetName(),
        HttpMethod::OPTIONS.GetName(),
        HttpMethod::TRACE.GetName(),
        HttpMethod::PATCH.GetName(),

    };

    return standardMethods.contains(method.GetName());
}