/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/Http/HttpCookie.h>

#include <sstream>

using namespace Vnet;
using namespace Vnet::Http;

HttpCookie::HttpCookie() : HttpCookie("", "") { }

HttpCookie::HttpCookie(const std::string_view name, const std::string_view value) {

    this->m_name = name;
    this->m_value = value;
    this->m_expirationDate = std::nullopt;
    this->m_maxAge = std::nullopt;
    this->m_domain = std::nullopt;
    this->m_path = std::nullopt;
    this->m_secure = std::nullopt;
    this->m_httpOnly = std::nullopt;
    this->m_sameSite = std::nullopt;

}

HttpCookie::HttpCookie(const HttpCookie& cookie) {
    this->operator= (cookie);
}

HttpCookie::HttpCookie(HttpCookie&& cookie) noexcept {
    this->operator= (std::move(cookie));
}

HttpCookie::~HttpCookie() { }

HttpCookie& HttpCookie::operator= (const HttpCookie& cookie) {

    if (this != &cookie) {
        this->m_name = cookie.m_name;
        this->m_value = cookie.m_value;
        this->m_expirationDate = cookie.m_expirationDate;
        this->m_maxAge = cookie.m_maxAge;
        this->m_domain = cookie.m_domain;
        this->m_path = cookie.m_path;
        this->m_secure = cookie.m_secure;
        this->m_httpOnly = cookie.m_httpOnly;
        this->m_sameSite = cookie.m_sameSite;
    }

    return static_cast<HttpCookie&>(*this);
}

HttpCookie& HttpCookie::operator= (HttpCookie&& cookie) noexcept {

    if (this != &cookie) {
        this->m_name = std::move(cookie.m_name);
        this->m_value = std::move(cookie.m_value);
        this->m_expirationDate = cookie.m_expirationDate;
        this->m_maxAge = cookie.m_maxAge;
        this->m_domain = std::move(cookie.m_domain);
        this->m_path = std::move(cookie.m_path);
        this->m_secure = cookie.m_secure;
        this->m_httpOnly = cookie.m_httpOnly;
        this->m_sameSite = cookie.m_sameSite;
    }

    return static_cast<HttpCookie&>(*this);
}

bool HttpCookie::operator== (const HttpCookie& cookie) const {

    if (this->m_name != cookie.m_name) return false;
    if (this->m_value != cookie.m_value) return false;
    if (this->m_expirationDate != cookie.m_expirationDate) return false;
    if (this->m_maxAge != cookie.m_maxAge) return false;
    if (this->m_domain != cookie.m_domain) return false;
    if (this->m_path != cookie.m_path) return false;
    if (this->m_secure != cookie.m_secure) return false;
    if (this->m_httpOnly != cookie.m_httpOnly) return false;
    if (this->m_sameSite != cookie.m_sameSite) return false;

    return true;
}

const std::string& HttpCookie::GetName() const {
    return this->m_name;
}

const std::string& HttpCookie::GetValue() const {
    return this->m_value;
}

const std::optional<DateTime> HttpCookie::GetExpirationDate() const {
    return this->m_expirationDate;
}

const std::optional<std::int32_t> HttpCookie::GetMaxAge() const {
    return this->m_maxAge;
}

const std::optional<std::string>& HttpCookie::GetDomain() const {
    return this->m_domain;
}

const std::optional<std::string>& HttpCookie::GetPath() const {
    return this->m_path;
}

const std::optional<bool> HttpCookie::IsSecure() const {
    return this->m_secure;
}

const std::optional<bool> HttpCookie::IsHttpOnly() const {
    return this->m_httpOnly;
}

const std::optional<SameSiteAttribute> HttpCookie::GetSameSite() const {
    return this->m_sameSite;
}

void HttpCookie::SetName(const std::string_view name) {
    this->m_name = name;
}

void HttpCookie::SetValue(const std::string_view value) {
    this->m_value = value;
}

void HttpCookie::SetExpirationDate(const std::optional<DateTime> expirationDate) {
    this->m_expirationDate = expirationDate;
}

void HttpCookie::SetMaxAge(const std::optional<std::int32_t> maxAge) {
    this->m_maxAge = maxAge;
}

void HttpCookie::SetDomain(const std::optional<std::string_view> domain) {
    this->m_domain = domain;
}

void HttpCookie::SetPath(const std::optional<std::string_view> path) {
    this->m_path = path;
}

void HttpCookie::SetSecure(const std::optional<bool> secure) {
    this->m_secure = secure;
}

void HttpCookie::SetHttpOnly(const std::optional<bool> httpOnly) {
    this->m_httpOnly = httpOnly;
}

void HttpCookie::SetSameSite(const std::optional<SameSiteAttribute> sameSite) {
    this->m_sameSite = sameSite;
}

std::string HttpCookie::ToString() const {

    std::ostringstream stream;

    stream << this->m_name << "=" << this->m_value;

    if (this->m_expirationDate.has_value()) 
        stream << "; Expires=" << this->m_expirationDate->ToUTCString();

    if (this->m_maxAge.has_value())
        stream << "; Max-Age=" << this->m_maxAge.value();

    if (this->m_domain.has_value())
        stream << "; Domain=" << this->m_domain.value();

    if (this->m_path.has_value())
        stream << "; Path=" << this->m_path.value();

    if (this->m_sameSite.has_value()) {

        stream << "; SameSite=";

        switch (this->m_sameSite.value()) {

            case SameSiteAttribute::STRICT:
                stream << "Strict";
                break;

            case SameSiteAttribute::LAX:
                stream << "Lax";
                break;

            case SameSiteAttribute::NONE:
                stream << "None";
                break;

        }

    }

    if (this->m_secure.value_or(false))
        stream << "; Secure";

    if (this->m_httpOnly.value_or(false))
        stream << "; HttpOnly";

    return stream.str();
}