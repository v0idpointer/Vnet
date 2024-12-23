/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/Http/HttpHeader.h>

#include <algorithm>
#include <sstream>
#include <exception>
#include <stdexcept>

using namespace Vnet::Http;

HttpHeader::HttpHeader() : m_name("X-Myheader"), m_value("") { }

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
        throw std::invalid_argument("Empty header name.");

    std::string_view::const_iterator it;
    it = std::find_if(name.begin(), name.end(), [] (const char ch) -> bool {
        
        if ((ch >= 'A') && (ch <= 'Z')) return false;
        if ((ch >= 'a') && (ch <= 'z')) return false;
        if ((ch >= '0') && (ch <= '9')) return false;
        if (ch == '-') return false;

        return true;
    });

    if (it != name.end()) 
        throw std::invalid_argument("Invalid character(s) in header name.");

    this->m_name = name;

    bool capitalize = true;
    for (std::size_t i = 0; i < this->m_name.length(); ++i) {

        char& ch = this->m_name[i];
        
        if (ch == '-') {
            capitalize = true;
            continue;
        }

        if (capitalize && ((ch >= 'a') && (ch <= 'z')))
            ch -= ('a' - 'A');

        if (!capitalize && ((ch >= 'A') && (ch <= 'Z')))
            ch += ('a' - 'A');

        capitalize = false;

    }

}

void HttpHeader::SetValue(const std::string_view value) {
    
    std::string_view::const_iterator it;
    it = std::find_if(value.begin(), value.end(), [] (const char ch) -> bool {

        if ((ch >= 'A') && (ch <= 'Z')) return false;
        if ((ch >= 'a') && (ch <= 'z')) return false;
        if ((ch >= '0') && (ch <= '9')) return false;

        if ((ch == '!') || (ch == '#') || (ch == '$') || (ch == '%')) return false;
        if ((ch == '&') || (ch == '\'') || (ch == '(') || (ch == ')')) return false;
        if ((ch == '*') || (ch == '+') || (ch == ',') || (ch == '-')) return false;
        if ((ch == '.') || (ch == '/') || (ch == ':') || (ch == ';')) return false;
        if ((ch == '<') || (ch == '=') || (ch == '>') || (ch == '?')) return false;
        if ((ch == '@') || (ch == '[') || (ch == ']') || (ch == '^')) return false;
        if ((ch == '_') || (ch == '`') || (ch == '{') || (ch == '|')) return false;
        if ((ch == '}') || (ch == '~') || (ch == ' ')) return false;

        return true;
    });

    if (it != value.end())
        throw std::invalid_argument("Invalid character(s) in header value.");

    this->m_value = value;

}

std::string HttpHeader::ToString() const {

    std::ostringstream stream;
    stream << this->m_name << ": " << this->m_value;

    return stream.str();
}

std::optional<HttpHeader> HttpHeader::ParseHeader(std::string_view str, const bool exceptions) {

    std::size_t pos = 0;

    if (str.empty()) {
        if (exceptions) throw std::invalid_argument("Empty string.");
        return std::nullopt;
    }

    if ((pos = str.find(": ")) == std::string_view::npos) {
        if (exceptions) throw std::runtime_error("Bad HTTP header.");
        return std::nullopt;
    }

    HttpHeader header;

    const std::string_view name = str.substr(0, pos);
    try { header.SetName(name); }
    catch (const std::exception&) {
        if (exceptions) throw std::runtime_error("Bad HTTP header.");
        return std::nullopt;
    }

    const std::string_view value = str.substr(pos + 2);
    try { header.SetValue(value); }
    catch (const std::exception&) {
        if (exceptions) throw std::runtime_error("Bad HTTP header.");
        return std::nullopt;
    }

    return header;
}

HttpHeader HttpHeader::Parse(const std::string_view str) {
    return HttpHeader::ParseHeader(str, true).value();
}

std::optional<HttpHeader> HttpHeader::TryParse(const std::string_view str) {
    return HttpHeader::ParseHeader(str, false);
}