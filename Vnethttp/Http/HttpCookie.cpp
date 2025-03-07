/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Http/HttpCookie.h>
#include <Vnet/Http/HttpParserException.h>
#include <Vnet/Util/String.h>

#include <sstream>
#include <vector>
#include <algorithm>
#include <unordered_set>

using namespace Vnet;
using namespace Vnet::Http;

HttpCookie::HttpCookie() : HttpCookie("NewCookie", "") { }

HttpCookie::HttpCookie(const std::string_view name, const std::string_view value) {

    this->SetName(name);
    this->SetValue(value);

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

    if (name.empty())
        throw std::invalid_argument("'name': Empty string.");

    const std::unordered_set<char> specialCharacters = {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~'
    };

    std::string_view::const_iterator it;
    it = std::find_if(name.begin(), name.end(), [&] (const char ch) -> bool {

        if ((ch >= 'A') && (ch <= 'Z')) return false;
        if ((ch >= 'a') && (ch <= 'z')) return false;
        if ((ch >= '0') && (ch <= '9')) return false;
        if (specialCharacters.contains(ch)) return false;

        return true;
    });

    if (it != name.end()) 
        throw std::invalid_argument("'name': Invalid cookie name.");

    this->m_name = name;

}

void HttpCookie::SetValue(const std::string_view value) {

    std::string_view::const_iterator it;
    it = std::find_if(value.begin(), value.end(), [] (const char ch) -> bool {
        if ((ch >= 0x20) && (ch < 0x7F)) return false;
        else return true;
    });

    if (it != value.end())
        throw std::invalid_argument("'value': Invalid cookie value.");

    this->m_value = value;

}

void HttpCookie::SetExpirationDate(const std::optional<DateTime> expirationDate) {
    this->m_expirationDate = expirationDate;
}

void HttpCookie::SetMaxAge(const std::optional<std::int32_t> maxAge) {
    this->m_maxAge = maxAge;
}

void HttpCookie::SetDomain(const std::optional<std::string_view> domain) {
    if (domain.has_value()) this->m_domain = ToLowercase(domain.value());
    else this->m_domain = std::nullopt;
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

    if (sameSite.has_value()) {

        switch (sameSite.value()) {

        case SameSiteAttribute::NONE:
        case SameSiteAttribute::LAX:
        case SameSiteAttribute::STRICT:
            break;

        default:
            throw std::invalid_argument("'sameSite': Invalid value.");

        }

    }

    this->m_sameSite = sameSite;

}

std::string HttpCookie::ToString() const {

    std::ostringstream stream;

    stream << this->m_name << "=" << HttpCookie::CharacterEscapeValue(this->m_value);

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

// this is fucking horrible
bool HttpCookie::IsValidValue(std::string_view str) {
    
    // check if the string contains control characters:
    std::string_view::const_iterator it;
    it = std::find_if(str.begin(), str.end(), [] (const char ch) -> bool {
        if ((ch >= 0x20) && (ch < 0x7F)) return false;
        else return true;
    });

    if (it != str.end()) return false;

    // string is quoted: check if backslashes are followed either by another backslash or a double quote marks.
    if (str.starts_with('"') && str.ends_with('"') && (!str.ends_with("\\\"") || str.ends_with("\\\\\""))) {

        str = str.substr(1, str.length() - 2);
        it = std::find_if(str.begin(), str.end(), [=] (const char& ch) -> bool {
            
            if (ch == '\\') {

                const char& next = *(std::next(&ch));

                if (&ch != str.data() && (*(std::prev(&ch)) == '\\'))
                    return false;

                return ((next != '"') && (next != '\\'));
            }
            
            return false;
        });

        return (it == str.end());
    }

    // string is not quoted: check if it contains any of the following disallowed characters.
    else {

        const std::unordered_set<char> specialCharacters = {
            ' ', ',', ';', '(', ')', '<', '>', '@', ':', '\\', '"', '/',
            '[', ']', '?', '=', '{', '}'
        };

        it = std::find_if(str.begin(), str.end(), [&] (const char ch) -> bool {
            return specialCharacters.contains(ch);
        });

        return (it == str.end());
    }

}

std::string HttpCookie::CharacterEscapeValue(std::string_view str) {

    const std::unordered_set<char> specialCharacters = {
        ' ', ',', ';', '(', ')', '<', '>', '@', ':', '\\', '"', '/',
        '[', ']', '?', '=', '{', '}'
    };

    std::string_view::const_iterator it;
    it = std::find_if(str.begin(), str.end(), [&] (const char ch) -> bool {
        return specialCharacters.contains(ch);
    });

    if (it == str.end()) return std::string(str);

    std::ostringstream stream;
    stream << '"';

    for (std::size_t i = 0; i < str.length(); ++i) {
        if ((str[i] == '\\') || str[i] == '"') stream << '\\' << str[i];
        else stream << str[i];
    }

    stream << '"';

    return stream.str();
}

std::string HttpCookie::CharacterUnescapeValue(std::string_view str) {
    
    str = str.substr(1, str.length() - 2);

    std::ostringstream stream;
    for (std::size_t i = 0; i < str.length(); ++i) {

        if (str[i] == '\\') { 
            stream << str[i + 1];
            ++i;
        }
        else stream << str[i];

    }

    return stream.str();
}

void HttpCookie::ParseCookieAttribute(HttpCookie& cookie, std::string_view attrib, const HttpParserOptions& options) {

    if (CaseInsensitiveStartsWith(attrib, "Expires=")) {

        std::string str = std::string(attrib.substr(8));
        std::transform(str.begin(), str.end(), str.begin(), [] (const char ch) -> char {
            return ((ch == '-') ? ' ' : ch);
        });

        const std::optional<DateTime> date = DateTime::TryParseUTCDate(str);
        if (!date.has_value()) 
            throw std::runtime_error("'Expires' attribute: bad datetime format.");

        cookie.SetExpirationDate(date);

        return;
    }

    if (CaseInsensitiveStartsWith(attrib, "Max-Age=")) {
        
        std::int32_t maxAge = 0;
        try { maxAge = std::stoi(attrib.substr(8).data()); }
        catch (const std::invalid_argument&) {
            throw std::runtime_error("'Max-Age' attribute: invalid value.");
        }
        catch (const std::out_of_range&) {
            throw std::runtime_error("'Max-Age' attribute: value out of range.");
        }

        cookie.SetMaxAge(maxAge);

        return;
    }

    if (CaseInsensitiveStartsWith(attrib, "Domain=")) {
        
        try { cookie.SetDomain(attrib.substr(7)); }
        catch (const std::exception&) {
            throw std::runtime_error("'Domain' attribute: URI malformed.");
        }

        return;
    }

    if (CaseInsensitiveStartsWith(attrib, "Path=")) {
        
        try { cookie.SetPath(attrib.substr(5)); }
        catch (const std::exception&) {
            throw std::runtime_error("'Path' attribute: URI malformed.");
        }

        return;
    }

    if (CaseInsensitiveStartsWith(attrib, "SameSite=")) {
        
        attrib = attrib.substr(9);

        if (EqualsIgnoreCase(attrib, "None")) cookie.SetSameSite(SameSiteAttribute::NONE);
        else if (EqualsIgnoreCase(attrib, "Lax")) cookie.SetSameSite(SameSiteAttribute::LAX);
        else if (EqualsIgnoreCase(attrib, "Strict")) cookie.SetSameSite(SameSiteAttribute::STRICT);
        else throw std::runtime_error("'SameSite' attribute: invalid value.");

        return;
    }

    if (EqualsIgnoreCase(attrib, "Secure")) {
        cookie.SetSecure(true);
        return;
    }

    if (EqualsIgnoreCase(attrib, "HttpOnly")) {
        cookie.SetHttpOnly(true);
        return;
    }

    if (!options.IgnoreNonstandardCookieAttributes) {

        std::size_t pos = attrib.find('=');
        if (pos != std::string_view::npos) 
            attrib = attrib.substr(0, pos);

        std::ostringstream stream;
        stream << "'" << attrib << "' attribute: invalid attribute.";

        throw std::runtime_error(stream.str());

    }

}

static std::vector<std::string> SplitString(const std::string_view str, const bool lenient) {

    std::vector<std::string> strings = { };
    std::ostringstream stream;
    bool quotes = false;

    for (std::size_t i = 0; i < str.length(); ++i) {

        if ((str[i] == '"') && ((i == 0) || (str[i - 1] != '\\'))) {
            quotes = !quotes;
            stream << '"';
        }
        else if ((str[i] == ';') && !quotes && (i < str.length()) && (lenient || (str[i + 1] == ' '))) {
            
            strings.push_back(stream.str());
            stream.str("");
            
            if (str[i + 1] == ' ') ++i;

        }
        else stream << str[i];

    }

    strings.push_back(stream.str());

    return strings;
}

std::optional<HttpCookie> HttpCookie::ParseCookie(std::string_view str, const HttpParserOptions& options, const bool exceptions) {

    if (str.empty()) {
        if (exceptions) throw std::invalid_argument("'str': Empty string.");
        return std::nullopt;
    }

    std::size_t pos = 0;
    std::vector<std::string> v = { };
    v = SplitString(str, options.IgnoreMissingWhitespaceAfterCookieAttributeSeparator);

    pos = v[0].find('=');
    const std::string name = v[0].substr(0, pos);
    const std::string value = v[0].substr(pos + 1);

    if (pos == std::string::npos) {
        if (exceptions) throw HttpParserException("HTTP parser error: bad HTTP cookie.", std::nullopt);
        return std::nullopt;
    }

    HttpCookie cookie;

    if (!options.BypassIsValidCookieValueCheck && !HttpCookie::IsValidValue(value)) {
        if (exceptions) throw HttpParserException("HTTP parser error: bad HTTP cookie: bad cookie value.", std::nullopt);
        return std::nullopt;
    }

    try { cookie.SetName(name); }
    catch (const std::invalid_argument&) {
        if (exceptions) throw HttpParserException("HTTP parser error: bad HTTP cookie: bad cookie name.", std::nullopt);
        return std::nullopt;
    }

    try { 
        
        if (value.starts_with('"') && value.ends_with('"') && (!str.ends_with("\\\"") || str.ends_with("\\\\\"")))
            cookie.SetValue(HttpCookie::CharacterUnescapeValue(value));
        else cookie.SetValue(value);

    }
    catch (const std::invalid_argument&) {
        if (exceptions) throw HttpParserException("HTTP parser error: bad HTTP cookie: bad cookie value.", std::nullopt);
        return std::nullopt;
    }

    for (std::size_t i = 1; i < v.size(); ++i) {

        try { HttpCookie::ParseCookieAttribute(cookie, v[i], options); }
        catch (const std::exception& ex) {

            using namespace std::string_literals;
            if (exceptions) throw HttpParserException(
                ("HTTP parser error: bad HTTP cookie: "s + ex.what()),
                std::nullopt
            );

            return std::nullopt;
        }

    }

    return cookie;
}

HttpCookie HttpCookie::Parse(const std::string_view str) {
    return HttpCookie::Parse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

HttpCookie HttpCookie::Parse(const std::string_view str, const HttpParserOptions& options) {
    return HttpCookie::ParseCookie(str, options, true).value();
}

std::optional<HttpCookie> HttpCookie::TryParse(const std::string_view str) {
    return HttpCookie::TryParse(str, HttpParserOptions::DEFAULT_OPTIONS);
}

std::optional<HttpCookie> HttpCookie::TryParse(const std::string_view str, const HttpParserOptions& options) {
    return HttpCookie::ParseCookie(str, options, false);
}