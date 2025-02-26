/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Http/HttpHeader.h>
#include <Vnet/Http/HttpParserException.h>

#include <algorithm>
#include <sstream>

using namespace Vnet::Http;

HttpHeader::HttpHeader() { 
    this->SetName("x-my-header");
    this->SetValue("");
}

HttpHeader::HttpHeader(const std::string_view name, const std::string_view value) {
    this->SetName(name);
    this->SetValue(value);
}

HttpHeader::HttpHeader(const HttpHeader& header) {
    this->operator= (header);
}

HttpHeader::HttpHeader(HttpHeader&& header) noexcept {
    this->operator= (std::move(header));
}

HttpHeader::~HttpHeader() { }

HttpHeader& HttpHeader::operator= (const HttpHeader& header) {

    if (this != &header) {
        this->m_name = header.m_name;
        this->m_value = header.m_value;
    }

    return static_cast<HttpHeader&>(*this);
}

HttpHeader& HttpHeader::operator= (HttpHeader&& header) noexcept {

    if (this != &header) {
        this->m_name = std::move(header.m_name);
        this->m_value = std::move(header.m_value);
    }

    return static_cast<HttpHeader&>(*this);
}

bool HttpHeader::operator== (const HttpHeader& header) const {
    
    if (this->m_value != header.m_value) return false;

    // case insensitive string compare
    return std::equal(
        this->m_name.begin(),
        this->m_name.end(),
        header.m_name.begin(),
        header.m_name.end(),
        [] (char a, char b) -> bool {
            if ((a >= 'A') && (a <= 'Z')) a += ('a' - 'A');
            if ((b >= 'A') && (b <= 'Z')) b += ('a' - 'A');
            return (a == b);
        }
    );

}

const std::string& HttpHeader::GetName() const {
    return this->m_name;
}

const std::string& HttpHeader::GetValue() const {
    return this->m_value;
}

void HttpHeader::SetName(const std::string_view name) {

    if (name.empty()) 
        throw std::invalid_argument("'name': Empty string.");

    std::string_view::const_iterator it;
    it = std::find_if(name.begin(), name.end(), [] (const char ch) -> bool {
        
        if ((ch >= 'A') && (ch <= 'Z')) return false;
        if ((ch >= 'a') && (ch <= 'z')) return false;
        if ((ch >= '0') && (ch <= '9')) return false;
        if (ch == '-') return false;

        return true;
    });

    if (it != name.end()) 
        throw std::invalid_argument("'name': Invalid header name.");

    this->m_name = name;

    for (std::size_t i = 0; i < this->m_name.length(); ++i) {

        char& ch = this->m_name[i];
        if ((ch >= 'A') && (ch <= 'Z'))
            ch += ('a' - 'A');

    }

}

void HttpHeader::SetValue(const std::string_view value) {
    
    std::string_view::const_iterator it;
    it = std::find_if(value.begin(), value.end(), [] (const char ch) -> bool {
        if ((ch >= 0x20) && (ch < 0x7F)) return false; // only printable ascii characters.
        else return true;
    });

    if (it != value.end())
        throw std::invalid_argument("'value': Invalid header value.");

    this->m_value = value;

}

std::string HttpHeader::ToString() const {

    std::ostringstream stream;
    stream << this->m_name << ": " << this->m_value;

    return stream.str();
}

std::optional<HttpHeader> HttpHeader::ParseHeader(std::string_view str, const HttpParserOptions& options, const bool exceptions) {

    std::size_t pos = 0;

    if (str.empty()) {
        if (exceptions) throw std::invalid_argument("'str': Empty string.");
        return std::nullopt;
    }

    if ((pos = str.find(": ")) == std::string_view::npos) {
        
        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad HTTP header.",
            HttpStatusCode::BAD_REQUEST
        );

        return std::nullopt;
    }

    const std::string_view name = str.substr(0, pos);
    const std::string_view value = str.substr(pos + 2);

    if (options.MaxHeaderNameLength && (name.length() > *options.MaxHeaderNameLength)) {
        
        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad HTTP header: header name too long.",
            HttpStatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );

        return std::nullopt;
    }

    if (options.MaxHeaderValueLength && (value.length() > *options.MaxHeaderValueLength)) {
        
        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad HTTP header: header value too long.",
            HttpStatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        
        return std::nullopt;
    }

    HttpHeader header;
    
    try { header.SetName(name); }
    catch (const std::invalid_argument&) {

        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad HTTP header: invalid header name.",
            HttpStatusCode::BAD_REQUEST
        );

        return std::nullopt;
    }

    try { header.SetValue(value); }
    catch (const std::invalid_argument& ex) {
        
        if (exceptions) throw HttpParserException(
            "HTTP parser error: bad HTTP header: invalid header value.",
            HttpStatusCode::BAD_REQUEST
        );

        return std::nullopt;
    }
    
    return header;
}

HttpHeader HttpHeader::Parse(const std::string_view str) {
    return HttpHeader::Parse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

HttpHeader HttpHeader::Parse(const std::string_view str, const HttpParserOptions& options) {
    return HttpHeader::ParseHeader(str, options, true).value();
}

std::optional<HttpHeader> HttpHeader::TryParse(const std::string_view str) {
    return HttpHeader::TryParse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

std::optional<HttpHeader> HttpHeader::TryParse(const std::string_view str, const HttpParserOptions& options) {
    return HttpHeader::ParseHeader(str, options, false);
}