/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/Uri.h>
#include <Vnet/BadUriException.h>

#include <algorithm>
#include <sstream>

using namespace Vnet;

Uri::Uri() : Uri("/") { }

Uri::Uri(const std::string_view uri) {
    this->ParseUri(uri);
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

void Uri::ParseUri(std::string_view uri) {

    std::size_t pos;
    std::string::const_iterator it;

    if (Uri::ContainsInvalidCharacters(uri)) throw BadUriException("URI contains invalid characters.");

    // parse the scheme component:
    if ((pos = uri.find(':')) != std::string_view::npos) {

        this->m_scheme = uri.substr(0, pos);
        it = std::find_if(this->m_scheme->begin(), this->m_scheme->end(), [] (const char ch) -> bool {
            
            if ((ch >= 'A') && (ch <= 'Z')) return false;
            if ((ch >= 'a') && (ch <= 'z')) return false;
            if ((ch >= '0') && (ch <= '9')) return false;
            if ((ch == '+') || (ch == '.') || (ch == '-')) return false;

            return true;
        });

        if (this->m_scheme->empty()) throw BadUriException("URI scheme cannot be an empty string.");
        if (it != this->m_scheme->end()) throw BadUriException("URI scheme contains invalid characters.");

        uri = uri.substr(pos + 1);

    }

    // parse the authority component:
    if (uri.starts_with("//")) {

        std::string_view authority;

        uri = uri.substr(2);
        pos = std::min(uri.find('/'), std::min(uri.find('?'), uri.find('#')));
        if (pos != std::string_view::npos) {
            authority = uri.substr(0, pos);
            uri = uri.substr(pos);
        }
        else {
            authority = uri;
            uri = "";
        }

        // parse the userinfo component:
        if ((pos = authority.find('@')) != std::string_view::npos) {
            this->m_userInfo = authority.substr(0, pos);
            authority = authority.substr(pos + 1);
        }

        // parse the port component:
        if ((pos = authority.rfind(':')) != std::string_view::npos) {
            
            std::size_t bracketPos = authority.rfind(']');                          // check if the last colon character
            if ((bracketPos == std::string_view::npos) || (pos > bracketPos)) {     // is not a part of an IPv6 address.

                const std::string port(authority.substr(pos + 1));
                authority = authority.substr(0, pos);

                it = std::find_if(port.begin(), port.end(), [] (const char ch) -> bool {
                    return (!(ch >= '0') || !(ch <= '9'));
                });

                if (it != port.end()) throw BadUriException("URI port cannot be a non-numerical value.");
                this->m_port = static_cast<std::uint16_t>(std::stoul(port));

            }

        }

        // parse the host component:
        if (authority.empty()) throw BadUriException("URI host cannot be an empty string.");
        this->m_host = authority;

    }

    if (uri.empty()) return;

    // parse the path component:
    pos = std::min(uri.find('?'), uri.find('#'));
    if (pos == std::string_view::npos) {
        this->m_path = uri;
        return;
    }

    this->m_path = uri.substr(0, pos);
    uri = uri.substr(pos);

    if (uri.empty()) return;

    // parse the query string component:
    if (uri[0] == '?') {
        
        std::string_view query = uri;
        if ((pos = query.find('#')) != std::string_view::npos) {
            query = query.substr(0, pos);
            uri = uri.substr(pos);
        }

        this->m_query = query.substr(1);

    }

    if (uri.empty()) return;

    // parse the fragment component:
    if (uri[0] == '#') this->m_fragment = uri.substr(1);

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