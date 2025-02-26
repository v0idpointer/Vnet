/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef VNET_BUILD_VNETHTTP
#define VNET_BUILD_VNETHTTP
#endif

#include <Vnet/Http/HttpHeaderCollection.h>
#include <Vnet/Http/HttpParserException.h>

#include <algorithm>
#include <vector>
#include <sstream>

using namespace Vnet::Http;

const std::string_view HttpHeaderCollection::SPECIAL_HEADERS[] = { "Set-Cookie", };

HttpHeaderCollection::HttpHeaderCollection() {
    this->m_headers = { };
}

HttpHeaderCollection::HttpHeaderCollection(const HttpHeaderCollection& headers) {
    this->operator= (headers);
}

HttpHeaderCollection::HttpHeaderCollection(HttpHeaderCollection&& headers) noexcept {
    this->operator= (std::move(headers));
}

HttpHeaderCollection::~HttpHeaderCollection() { }

HttpHeaderCollection& HttpHeaderCollection::operator= (const HttpHeaderCollection& headers) {
    if (this != &headers) this->m_headers = { headers.m_headers.begin(), headers.m_headers.end() };
    return static_cast<HttpHeaderCollection&>(*this);
}

HttpHeaderCollection& HttpHeaderCollection::operator= (HttpHeaderCollection&& headers) noexcept {
    if (this != &headers) this->m_headers = std::move(headers.m_headers);
    return static_cast<HttpHeaderCollection&>(*this);
}

bool HttpHeaderCollection::operator== (const HttpHeaderCollection& headers) const {
    return (this->ToString() == headers.ToString());
}

static inline bool StrEqualsIgnoreCase(const std::string_view lhs, const std::string_view rhs) noexcept {

    return std::equal(
        lhs.begin(),
        lhs.end(),
        rhs.begin(),
        rhs.end(),
        [] (char a, char b) -> bool {
            if ((a >= 'A') && (a <= 'Z')) a += ('a' - 'A');
            if ((b >= 'A') && (b <= 'Z')) b += ('a' - 'A');
            return (a == b);
        }
    );

}

std::list<HttpHeader>::const_iterator HttpHeaderCollection::begin() const {
    return this->m_headers.begin();
}

std::list<HttpHeader>::const_iterator HttpHeaderCollection::end() const {
    return this->m_headers.end();
}

const HttpHeader& HttpHeaderCollection::Get(const std::string_view name) const {
    
    std::list<HttpHeader>::const_iterator it;
    it = std::find_if(this->m_headers.begin(), this->m_headers.end(), [=] (const HttpHeader& header) -> bool {
        return StrEqualsIgnoreCase(header.GetName(), name);
    });

    if (it == this->m_headers.end())
        throw std::out_of_range("The specified header does not exist.");

    return static_cast<const HttpHeader&>(*it);
}

HttpHeader& HttpHeaderCollection::Get(const std::string_view name) {
    return const_cast<HttpHeader&>(static_cast<const HttpHeaderCollection&>(*this).Get(name));
}

std::int32_t HttpHeaderCollection::Count() const {
    return static_cast<std::int32_t>(this->m_headers.size());
}

bool HttpHeaderCollection::Contains(const std::string_view name) const {
    
    std::list<HttpHeader>::const_iterator it;
    it = std::find_if(this->m_headers.begin(), this->m_headers.end(), [&] (const HttpHeader& header) -> bool {
        return StrEqualsIgnoreCase(name, header.GetName());
    });

    return (it != this->m_headers.end());
}

bool HttpHeaderCollection::Contains(const HttpHeader& header) const {
    
    std::list<HttpHeader>::const_iterator it;
    it = std::find(this->m_headers.begin(), this->m_headers.end(), header);

    return (it != this->m_headers.end());
}

bool HttpHeaderCollection::IsSpecialHeader(const std::string_view name) {

    const std::string_view* const begin = std::begin(HttpHeaderCollection::SPECIAL_HEADERS);
    const std::string_view* const end = std::end(HttpHeaderCollection::SPECIAL_HEADERS);

    const std::string_view* it;
    it = std::find_if(begin, end, [=] (const std::string_view str) -> bool {
        return StrEqualsIgnoreCase(str, name);
    });

    return (it != end);
}

void HttpHeaderCollection::AppendHeaderValue(const std::string_view name, const std::string_view value) {

    std::list<HttpHeader>::iterator it;
    it = std::find_if(this->m_headers.begin(), this->m_headers.end(), [=] (const HttpHeader& header) -> bool {
        return StrEqualsIgnoreCase(header.GetName(), name);
    });

    if (it == this->m_headers.end()) throw std::runtime_error("AppendHeaderValue: it == this->m_headers.end()");

    std::ostringstream stream;
    stream << it->GetValue() << ", " << value;

    it->SetValue(stream.str());

}

void HttpHeaderCollection::Add(const std::string_view name, const std::string_view value, const bool force) { 
    
    bool append = (!force && !HttpHeaderCollection::IsSpecialHeader(name));
    if (append && !this->Contains(name)) append = false;

    if (append) this->AppendHeaderValue(name, value);
    else this->m_headers.push_back({ name, value });

}

void HttpHeaderCollection::Add(const std::string_view name, const std::string_view value) { 
    this->Add(name, value, false);
}

void HttpHeaderCollection::Add(const HttpHeader& header, const bool force) { 
    
    bool append = (!force && !HttpHeaderCollection::IsSpecialHeader(header.GetName()));
    if (append && !this->Contains(header.GetName())) append = false;

    if (append) this->AppendHeaderValue(header.GetName(), header.GetValue());
    else this->m_headers.push_back(header);

}

void HttpHeaderCollection::Add(const HttpHeader& header) { 
    this->Add(header, false);
}

void HttpHeaderCollection::Set(const std::string_view name, const std::string_view value) {
    this->Remove(name);
    this->m_headers.push_back({ name, value });
}

void HttpHeaderCollection::Set(const HttpHeader& header) {
    this->Remove(header.GetName());
    this->m_headers.push_back({ header.GetName(), header.GetValue() });
}

void HttpHeaderCollection::Set(HttpHeader&& header) noexcept {
    this->Remove(header.GetName());
    this->m_headers.push_back(std::move(header));
}

void HttpHeaderCollection::Clear() {
    this->m_headers.clear();
}

void HttpHeaderCollection::Remove(const HttpHeader& header) {
    this->m_headers.remove(header);
}

void HttpHeaderCollection::Remove(const std::string_view name) {

    this->m_headers.remove_if([=] (const HttpHeader& header) -> bool {
        return StrEqualsIgnoreCase(header.GetName(), name);
    });

}

std::string HttpHeaderCollection::ToString() const {
    
    std::size_t pos = 0;
    std::vector<std::string> text = { };
    text.resize(this->m_headers.size());

    std::list<HttpHeader>::const_iterator it;
    for (it = this->m_headers.begin(); it != this->m_headers.end(); std::advance(it, 1))
        text[pos++] = it->ToString();

    std::sort(text.begin(), text.end());

    std::ostringstream stream;
    for (const std::string& str : text)
        stream << str << "\r\n";

    std::string str = stream.str();
    if (!str.empty()) str.erase(str.size() - 2);

    return str;
}

std::optional<HttpHeaderCollection> HttpHeaderCollection::ParseHeaders(std::string_view str, const HttpParserOptions& options, const bool exceptions) {

    std::size_t pos = 0;
    std::vector<std::string_view> v = { };

    if (str.empty()) {
        if (exceptions) throw std::invalid_argument("'str': Empty string.");
        return std::nullopt;
    }

    while ((pos = str.find("\r\n")) != std::string_view::npos) {
        v.push_back(str.substr(0, pos));
        str = str.substr(pos + 2);
    }
    v.push_back(str);

    if (options.MaxHeaderCount && v.size() > *options.MaxHeaderCount) {
        
        if (exceptions) throw HttpParserException(
            "HTTP parser error: too many HTTP headers.",
            HttpStatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        
        return std::nullopt;
    }

    HttpHeaderCollection collection;
    for (const std::string_view str : v) {

        std::optional<HttpHeader> header;
        try { header = HttpHeader::Parse(str, options); }
        catch (const HttpParserException& ex) {
            if (exceptions) throw HttpParserException(ex.what(), ex.GetStatusCode());
            return std::nullopt;
        }
        catch (const std::invalid_argument&) {
            if (exceptions) throw HttpParserException("HTTP parser error: bad HTTP header.", HttpStatusCode::BAD_REQUEST);
            return std::nullopt;
        }

        try { collection.Add(header.value(), !options.AppendHeadersWithIdenticalNames); }
        catch (const std::runtime_error& ex) {
            
            using namespace std::string_literals;
            if (exceptions) throw HttpParserException(
                ("HTTP parser error: internal error: "s + ex.what()),
                HttpStatusCode::INTERNAL_SERVER_ERROR
            );

            return std::nullopt;
        }

    }

    return collection;
}

HttpHeaderCollection HttpHeaderCollection::Parse(const std::string_view str) {
    return HttpHeaderCollection::Parse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

HttpHeaderCollection HttpHeaderCollection::Parse(const std::string_view str, const HttpParserOptions& options) {
    return HttpHeaderCollection::ParseHeaders(str, options, true).value();
}

std::optional<HttpHeaderCollection> HttpHeaderCollection::TryParse(const std::string_view str) {
    return HttpHeaderCollection::TryParse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

std::optional<HttpHeaderCollection> HttpHeaderCollection::TryParse(const std::string_view str, const HttpParserOptions& options) {
    return HttpHeaderCollection::ParseHeaders(str, options, false);
}