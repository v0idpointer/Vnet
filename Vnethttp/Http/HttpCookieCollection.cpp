/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Http/HttpCookieCollection.h>
#include <Vnet/Http/HttpParserException.h>

#include <vector>
#include <sstream>
#include <algorithm>

using namespace Vnet;
using namespace Vnet::Http;

HttpCookieCollection::HttpCookieCollection() { 
    this->m_cookies = { };
    this->m_dates = { };
}

HttpCookieCollection::HttpCookieCollection(const HttpCookieCollection& cookies) {
    this->operator= (cookies);
}

HttpCookieCollection::HttpCookieCollection(HttpCookieCollection&& cookies) noexcept {
    this->operator= (std::move(cookies));
}

HttpCookieCollection::~HttpCookieCollection() { }

HttpCookieCollection& HttpCookieCollection::operator= (const HttpCookieCollection& cookies) {
    
    if (this != &cookies) {
        this->m_cookies = { cookies.m_cookies.begin(), cookies.m_cookies.end() };
        this->m_dates = { cookies.m_dates.begin(), cookies.m_dates.end() };
    }

    return static_cast<HttpCookieCollection&>(*this);
}

HttpCookieCollection& HttpCookieCollection::operator= (HttpCookieCollection&& cookies) noexcept {
    
    if (this != &cookies) {
        this->m_cookies = std::move(cookies.m_cookies);
        this->m_dates = std::move(cookies.m_dates);
    }

    return static_cast<HttpCookieCollection&>(*this);
}

HttpCookieCollection::CookieSet::const_iterator HttpCookieCollection::begin() const {
    return this->m_cookies.begin();
}

HttpCookieCollection::CookieSet::const_iterator HttpCookieCollection::end() const {
    return this->m_cookies.end();
}

const HttpCookie& HttpCookieCollection::Get(const std::string_view name, const std::optional<std::string_view> domain, const std::optional<std::string_view> path) const {
    
    HttpCookie cookie;

    try { 
        cookie.SetName(name);
        cookie.SetDomain(domain);
        cookie.SetPath(path);
    }
    catch (const std::exception&) {
        throw std::out_of_range("The specified cookie does not exist.");
    }

    const HttpCookieCollection::CookieSet::const_iterator it = this->m_cookies.find(cookie);
    if (it == this->m_cookies.end()) throw std::out_of_range("The specified cookie does not exist.");

    return *it;
}

const HttpCookie& HttpCookieCollection::Get(const std::string_view name) const {
    
    for (const HttpCookie& cookie : this->m_cookies)
        if (cookie.GetName() == name)
            return cookie;

    throw std::out_of_range("The specified cookie does not exist.");
}

bool HttpCookieCollection::Contains(const std::string_view name, const std::optional<std::string_view> domain, const std::optional<std::string_view> path) const {

    HttpCookie cookie;

    try {
        cookie.SetName(name);
        cookie.SetDomain(domain);
        cookie.SetPath(path);
    }
    catch (const std::exception&) {
        return false;
    }

    const HttpCookieCollection::CookieSet::const_iterator it = this->m_cookies.find(cookie);
    
    return (it != this->m_cookies.end());
}

bool HttpCookieCollection::Contains(const std::string_view name) const {
    
    for (const HttpCookie& cookie : this->m_cookies)
        if (cookie.GetName() == name)
            return true;

    return false;
}

bool HttpCookieCollection::Contains(const HttpCookie& cookie) const {
    const HttpCookieCollection::CookieSet::const_iterator it = this->m_cookies.find(cookie);
    if (it == this->m_cookies.end()) return false;
    else return (*it == cookie);
}

std::int32_t HttpCookieCollection::Count() const {
    return this->m_cookies.size();
}

void HttpCookieCollection::Add(const HttpCookie& cookie) {
    
    if (this->m_cookies.contains(cookie)) {
        this->m_cookies.erase(cookie);
        this->m_dates.erase(cookie);
    }

    if (!cookie.GetValue().empty()) {
        this->m_cookies.insert(cookie);
        this->m_dates.insert({ cookie, DateTime::Now() });
    }

}

void HttpCookieCollection::Remove(const HttpCookie& cookie) {
    
    if (!this->Contains(cookie)) return;

    this->m_cookies.erase(cookie);
    this->m_dates.erase(cookie);

}

void HttpCookieCollection::RemoveExpired() {

    const DateTime now = DateTime::Now();

    std::erase_if(this->m_cookies, [&] (const HttpCookie& cookie) -> bool {

        if (!cookie.GetExpirationDate().has_value() && !cookie.GetMaxAge().has_value()) {
            this->m_dates.erase(cookie);
            return true;
        }

        if (cookie.GetMaxAge().has_value()) {

            const DateTime expires = (this->m_dates.at(cookie) + std::chrono::seconds(*cookie.GetMaxAge()));
            if (now >= expires) {
                this->m_dates.erase(cookie);
                return true;
            }

        }

        if (cookie.GetExpirationDate().has_value()) {

            if (now >= *cookie.GetExpirationDate()) {
                this->m_dates.erase(cookie);
                return true;
            }

        }

        return false;
    });

}

void HttpCookieCollection::Clear() {
    this->m_cookies.clear();
    this->m_dates.clear();
}

std::string HttpCookieCollection::ToString() const {

    std::ostringstream stream;
    for (const HttpCookie& cookie : this->m_cookies) {

        if (!stream.view().empty()) stream << "; ";

        // creating a duplicate is not the best idea, but i don't want to have
        // the fucking character escape logic here (again)...
        const HttpCookie c = { cookie.GetName(), cookie.GetValue() };
        stream << c.ToString();

    }

    return stream.str();
}

static std::vector<std::string> SplitString(const std::string_view str) {

    std::vector<std::string> strings = { };
    std::ostringstream stream;
    bool quotes = false;

    for (std::size_t i = 0; i < str.length(); ++i) {

        if ((str[i] == '"') && ((i == 0) || (str[i - 1] != '\\'))) {
            quotes = !quotes;
            stream << '"';
        }
        else if ((str[i] == ';') && !quotes && (i < str.length()) && (str[i + 1] == ' ')) {
            strings.push_back(stream.str());
            stream.str("");
            ++i;
        }
        else stream << str[i];

    }

    strings.push_back(stream.str());

    return strings;
}

std::optional<HttpCookieCollection> HttpCookieCollection::ParseCookieCollection(const std::string_view str, const HttpParserOptions& options, const bool exceptions) {

    if (str.empty())
        throw std::invalid_argument("'str': Empty string.");

    HttpCookieCollection collection = { };
    
    const std::vector<std::string> v = SplitString(str);
    for (const std::string& s : v) {

        HttpCookie cookie;
        try { cookie = HttpCookie::Parse(s, options); }
        catch (const HttpParserException& ex) {
            if (exceptions) throw HttpParserException(ex.what(), ex.GetStatusCode());
            return std::nullopt;
        }
        catch (const std::invalid_argument&) {
            if (exceptions) throw HttpParserException("HTTP parser error: bad HTTP cookie.", std::nullopt);
            return std::nullopt;
        }

        collection.Add(cookie);

    }

    return collection;
}

HttpCookieCollection HttpCookieCollection::Parse(const std::string_view str) {
    return HttpCookieCollection::Parse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

HttpCookieCollection HttpCookieCollection::Parse(const std::string_view str, const HttpParserOptions& options) {
    return HttpCookieCollection::ParseCookieCollection(str, options, true).value();
}

std::optional<HttpCookieCollection> HttpCookieCollection::TryParse(const std::string_view str) {
    return HttpCookieCollection::TryParse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

std::optional<HttpCookieCollection> HttpCookieCollection::TryParse(const std::string_view str, const HttpParserOptions& options) {
    return HttpCookieCollection::ParseCookieCollection(str, options, false);
}