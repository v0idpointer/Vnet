/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Uri.h>
#include <Vnet/BadUriException.h>

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <limits>

using namespace Vnet;

Uri::Uri() { 

    this->m_scheme = std::nullopt;
    this->m_userInfo = std::nullopt;
    this->m_host = std::nullopt;
    this->m_port = std::nullopt;
    this->m_path = "/";
    this->m_query = std::nullopt;
    this->m_fragment = std::nullopt;

}

Uri::Uri(const Uri& uri) {
    this->operator= (uri);
}

Uri::Uri(Uri&& uri) noexcept {
    this->operator= (std::move(uri));
}

Uri::~Uri() { }

Uri& Uri::operator= (const Uri& uri) {

    if (this != &uri) {
        this->m_scheme = uri.m_scheme;
        this->m_userInfo = uri.m_userInfo;
        this->m_host = uri.m_host;
        this->m_port = uri.m_port;
        this->m_path = uri.m_path;
        this->m_query = uri.m_query;
        this->m_fragment = uri.m_fragment;
    }

    return static_cast<Uri&>(*this);
}

Uri& Uri::operator= (Uri&& uri) noexcept {

    if (this != &uri) {
        this->m_scheme = std::move(uri.m_scheme);
        this->m_userInfo = std::move(uri.m_userInfo);
        this->m_host = std::move(uri.m_host);
        this->m_port = std::move(uri.m_port);
        this->m_path = std::move(uri.m_path);
        this->m_query = std::move(uri.m_query);
        this->m_fragment = std::move(uri.m_fragment);
    }

    return static_cast<Uri&>(*this);
}

bool Uri::operator== (const Uri& uri) const {
    
    if (this->m_scheme != uri.m_scheme) return false;
    if (this->m_userInfo != uri.m_userInfo) return false;
    if (this->m_host != uri.m_host) return false;
    if (this->m_port != uri.m_port) return false;
    if (this->m_path != uri.m_path) return false;
    if (this->m_query != uri.m_query) return false;
    if (this->m_fragment != uri.m_fragment) return false;

    return true;
}

const std::optional<std::string>& Uri::GetScheme() const {
    return this->m_scheme;
}

const std::optional<std::string>& Uri::GetUserInfo() const {
    return this->m_userInfo;
}

const std::optional<std::string>& Uri::GetHost() const {
    return this->m_host;
}

const std::optional<std::uint16_t> Uri::GetPort() const {
    return this->m_port;
}

const std::optional<std::string>& Uri::GetPath() const {
    return this->m_path;
}

const std::optional<std::string>& Uri::GetQuery() const {
    return this->m_query;
}

const std::optional<std::string>& Uri::GetFragment() const {
    return this->m_fragment;
}

bool Uri::IsAbsoluteUri() const {
    return (this->m_scheme != std::nullopt);
}

bool Uri::IsRelativeUri() const {
    return !this->IsAbsoluteUri();
}

std::string Uri::ToString() const {
    
    std::ostringstream stream;

    if (this->m_scheme.has_value()) stream << *this->m_scheme << ":";
    
    if (this->m_host.has_value()) {
        stream << "//";
        if (this->m_userInfo.has_value()) stream << *this->m_userInfo << "@";
        stream << *this->m_host;
        if (this->m_port.has_value()) stream << ":" << *this->m_port;
    }

    if (this->m_path.has_value()) stream << *this->m_path;
    if (this->m_query.has_value()) stream << "?" << *this->m_query;
    if (this->m_fragment.has_value()) stream << "#" << *this->m_fragment;

    return stream.str();
}

bool Uri::ContainsInvalidCharacters(const std::string_view uri) {

    const std::string_view::const_iterator it = std::find_if(uri.begin(), uri.end(), [] (const char ch) -> bool {

        // check for unreserved characters:
        if ((ch >= 'A') && (ch <= 'Z')) return false;
        if ((ch >= 'a') && (ch <= 'z')) return false;
        if ((ch >= '0') && (ch <= '9')) return false;
        if ((ch == '-') || (ch == '_') || (ch == '.') || (ch == '~')) return false;

        // check for reserved characters:
        if ((ch == ':') || (ch == '/') || (ch == '?') || (ch == '#') || (ch == '[') || (ch == ']') || (ch == '@')) return false;
		if ((ch == '!') || (ch == '$') || (ch == '&') || (ch == '\'') || (ch == '(') || (ch == ')')) return false;
		if ((ch == '*') || (ch == '+') || (ch == ',') || (ch == ';') || (ch == '=')) return false;

        if (ch == '%') return false;

        return true;
    });
    
    return (it != uri.end());
}

std::optional<Uri> Uri::ParseUri(std::string_view str, const bool exceptions) {
    
    Uri uri;
    std::size_t pos;
    std::string::const_iterator it;

    if (str.empty()) {
        if (exceptions) throw std::invalid_argument("'str': Empty string.");
        return std::nullopt;
    }

    if (Uri::ContainsInvalidCharacters(str)) {
        if (exceptions) throw BadUriException("Invalid character(s).");
        return std::nullopt;
    }

    // parse the scheme component:
    if ((pos = str.find(':')) != std::string_view::npos) {

        uri.m_scheme = str.substr(0, pos);
        it = std::find_if(uri.m_scheme->begin(), uri.m_scheme->end(), [] (const char ch) -> bool {
            
            if ((ch >= 'A') && (ch <= 'Z')) return false;
            if ((ch >= 'a') && (ch <= 'z')) return false;
            if ((ch >= '0') && (ch <= '9')) return false;
            if ((ch == '+') || (ch == '.') || (ch == '-')) return false;

            return true;
        });

        if (uri.m_scheme->empty()) {
            if (exceptions) throw BadUriException("Scheme empty.");
            return std::nullopt;
        }

        if (it != uri.m_scheme->end()) {
            if (exceptions) throw BadUriException("Invalid character(s) in scheme.");
            return std::nullopt;
        }

        str = str.substr(pos + 1);

    }

    // parse the authority component:
    if (str.starts_with("//")) {

        std::string_view authority;

        str = str.substr(2);
        pos = std::min(str.find('/'), std::min(str.find('?'), str.find('#')));
        if (pos != std::string_view::npos) {
            authority = str.substr(0, pos);
            str = str.substr(pos);
        }
        else {
            authority = str;
            str = "";
        }

        // parse the userinfo component:
        if ((pos = authority.find('@')) != std::string_view::npos) {
            uri.m_userInfo = authority.substr(0, pos);
            authority = authority.substr(pos + 1);
        }

        // parse the port component:
        if ((pos = authority.rfind(':')) != std::string_view::npos) {
            
            std::size_t bracketPos = authority.rfind(']');                          // check if the last colon character
            if ((bracketPos == std::string_view::npos) || (pos > bracketPos)) {     // is not a part of an IPv6 address.

                const std::string port(authority.substr(pos + 1));
                authority = authority.substr(0, pos);

                std::int32_t p = 0;
                try { p = std::stoi(port); }
                catch (const std::invalid_argument& ex) {
                    if (exceptions) throw BadUriException("Invalid port number.");
                    return std::nullopt;
                }
                catch (const std::out_of_range& ex) {
                    if (exceptions) throw BadUriException("Port out of range.");
                    return std::nullopt;
                }

                if ((p < 0) || (p > std::numeric_limits<std::uint16_t>::max())) {
                    if (exceptions) throw BadUriException("Port out of range.");
                    return std::nullopt;
                }

                uri.m_port = static_cast<std::uint16_t>(p);

            }

        }

        // parse the host component:
        if (!authority.empty()) uri.m_host = authority;

    }

    if (str.empty()) return uri;

    // parse the path component:
    pos = std::min(str.find('?'), str.find('#'));
    if (pos == std::string_view::npos) {
        
        if (str.find("//") != std::string_view::npos) {
            if (exceptions) throw BadUriException("Too many slashes.");
            return std::nullopt;
        }
        
        uri.m_path = str;
        return uri;

    }

    uri.m_path = str.substr(0, pos);
    str = str.substr(pos);

    if (uri.m_path->find("//") != std::string_view::npos) {
        if (exceptions) throw BadUriException("Too many slashes.");
        return std::nullopt;
    }

    if (str.empty()) return uri;

    // parse the query string component:
    if (str[0] == '?') {
        
        std::string_view query = str;
        if ((pos = query.find('#')) != std::string_view::npos) {
            query = query.substr(0, pos);
            str = str.substr(pos);
        }

        uri.m_query = query.substr(1);

    }

    if (str.empty()) return uri;

    // parse the fragment component:
    if (str[0] == '#') uri.m_fragment = str.substr(1);

    return uri;
}

Uri Uri::Parse(const std::string_view str) {
    return Uri::ParseUri(str, true).value();
}

std::optional<Uri> Uri::TryParse(const std::string_view str) {
    return Uri::ParseUri(str, false);
}

std::string Uri::Encode(const std::string_view str) {
    return Uri::Encode(str, true);
}

std::string Uri::Encode(const std::string_view str, const bool encodePathDelimiters) {

    bool (*isUnreservedChar)(const char, const bool) = [] (const char ch, const bool encodePathDelimiters) -> bool {

        if ((ch >= 'A') && (ch <= 'Z')) return true;
        if ((ch >= 'a') && (ch <= 'z')) return true;
        if ((ch >= '0') && (ch <= '9')) return true;
        if ((ch == '-') || (ch == '_') || (ch == '.') || (ch == '~')) return true;
        if (!encodePathDelimiters && (ch == '/')) return true;

        return false;
    };

    std::ostringstream stream;

    for (std::size_t i = 0; i < str.length(); ++i) {

        if (isUnreservedChar(str[i], encodePathDelimiters)) stream << str[i];
        else {
            const std::int32_t val = static_cast<std::int32_t>(str[i]);
            stream << '%' << std::setw(2) << std::setfill('0') << std::hex << val;
        }

    }

    return stream.str();
}

std::string Uri::Decode(const std::string_view str) {

    std::ostringstream stream;

    for (std::size_t i = 0; i < str.length(); ++i) {

        const char ch = str[i];

        if (ch != '%') {
            stream << ((ch == '+') ? ' ' : ch);
            continue;
        }

        const std::string s { str.substr((i + 1), 2) };

        std::int32_t val = 0;
        try { val = std::stoi(s, nullptr, 16); }
        catch (const std::exception&) {
            throw BadUriException("Bad percent-encoding.");
        }

        stream << static_cast<char>(val);
        i += 2;

    }

    return stream.str();
}

std::optional<std::string> Uri::TryDecode(const std::string_view str) {

    std::string decoded;
    try { decoded = Uri::Decode(str); }
    catch (const BadUriException&) {
        return std::nullopt;
    }

    return decoded;
}