/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Web/CookieStorage.h>
#include <Vnet/Http/HttpException.h>

using namespace Vnet;
using namespace Vnet::Http;
using namespace Vnet::Web;

CookieStorage::CookieStorage() {
    this->m_collections = { };
}

CookieStorage::CookieStorage(const CookieStorage& storage) {
    this->operator= (storage);
}

CookieStorage::CookieStorage(CookieStorage&& storage) noexcept {
    this->operator= (std::move(storage));
}

CookieStorage::~CookieStorage() { }

CookieStorage& CookieStorage::operator= (const CookieStorage& storage) {
    if (this != &storage) this->m_collections = { storage.m_collections.begin(), storage.m_collections.end() };
    return static_cast<CookieStorage&>(*this);
}

CookieStorage& CookieStorage::operator= (CookieStorage&& storage) noexcept {
    if (this != &storage) this->m_collections = std::move(storage.m_collections);
    return static_cast<CookieStorage&>(*this);
}

std::unordered_map<std::string, HttpCookieCollection>::const_iterator CookieStorage::begin() const {
    return this->m_collections.begin();
}

std::unordered_map<std::string, HttpCookieCollection>::const_iterator CookieStorage::end() const {
    return this->m_collections.end();
}

std::vector<std::string> CookieStorage::GetDomains(const Uri& uri) {

    std::vector<std::string> domains = { };
    std::string_view str;

    if (uri.GetHost().has_value())
        str = uri.GetHost().value();

    while (!str.empty()) {

        domains.push_back(str.data());

        std::size_t pos = str.find('.');
        if (pos == std::string_view::npos) break;
        else str = str.substr(pos + 1);

    }

    // TODO: maybe? more testing needed.
    // if (uri.GetHost().value_or("").find('.') != std::string::npos)
    //     domains.pop_back();

    return domains;
}

HttpCookieCollection CookieStorage::GetCookies(const Uri& requestUri) const {

    if (requestUri.IsRelativeUri())
        throw std::invalid_argument("'requestUri': Relative URI.");

    if ((requestUri.GetScheme() != "http") && (requestUri.GetScheme() != "https"))
        throw std::invalid_argument("'requestUri': Unsupported scheme.");

    if (!requestUri.GetHost().has_value())
        throw std::invalid_argument("'requestUri': Host component is std::nullopt.");

    const bool secure = (requestUri.GetScheme() == "https");

    HttpCookieCollection collection = { };
    for (const std::string& domain : CookieStorage::GetDomains(requestUri)) {

        if (!this->m_collections.contains(domain)) continue;
        
        const HttpCookieCollection& cookies = this->m_collections.at(domain);
        for (const HttpCookie& cookie : cookies) {

            if (!cookie.GetDomain().has_value() && (requestUri.GetHost().value() != domain)) continue;
            if (!requestUri.GetPath().value_or("/").starts_with(cookie.GetPath().value_or("/"))) continue;
            if (cookie.IsSecure().value_or(false) && !secure) continue;

            collection.Add(cookie);

        }

    }

    return collection;
}

void CookieStorage::AddCookie(const Uri& requestUri, HttpCookie cookie) {
    
    if (requestUri.IsRelativeUri())
        throw std::invalid_argument("'requestUri': Relative URI.");

    if ((requestUri.GetScheme() != "http") && (requestUri.GetScheme() != "https"))
        throw std::invalid_argument("'requestUri': Unsupported scheme.");

    if (!requestUri.GetHost().has_value())
        throw std::invalid_argument("'requestUri': Host component is std::nullopt.");

    if (cookie.GetDomain().has_value()) {

        std::string_view cookieDomain = cookie.GetDomain().value();
        if (cookieDomain.starts_with('.')) cookieDomain = cookieDomain.substr(1);
        if (!requestUri.GetHost().value().ends_with(cookieDomain))
            throw HttpException("Cookie rejected: domain mismatch.");

    }

    if (!cookie.GetPath().has_value()) {

        std::size_t pos = 0;
        std::string path = requestUri.GetPath().value_or("/");
        if ((path != "/") && path.ends_with('/')) path = path.substr(0, (path.length() - 1));
        if (((pos = path.rfind('/')) != std::string::npos) && (pos != 0))
            path = path.substr(0, pos);

        cookie.SetPath(path);

    }

    if (cookie.IsSecure().value_or(false) && (requestUri.GetScheme() != "https"))
        throw HttpException("Cookie rejected: 'Secure' cookie sent over HTTP.");

    if (cookie.GetName().starts_with("__Secure-") && !cookie.IsSecure().value_or(false))
        throw HttpException("Cookie rejected: '__Secure-' cookie not marked as 'Secure'.");

    if (cookie.GetName().starts_with("__Host-")) {

        if (!cookie.IsSecure().value_or(false) || cookie.GetDomain().has_value() || (cookie.GetPath().value_or("/") != "/"))
            throw HttpException("Cookie rejected: bad domain-locked cookie.");

    }

    std::string collectionName;
    if (cookie.GetDomain().has_value()) collectionName = cookie.GetDomain().value();
    else collectionName = requestUri.GetHost().value();

    if (!this->m_collections.contains(collectionName))
        this->m_collections.insert({ collectionName, HttpCookieCollection() });
    
    this->m_collections.at(collectionName).Add(cookie);

}

void CookieStorage::RemoveCookie(const Uri& requestUri, const HttpCookie& cookie) {

    if (requestUri.IsRelativeUri())
    throw std::invalid_argument("'requestUri': Relative URI.");

    if ((requestUri.GetScheme() != "http") && (requestUri.GetScheme() != "https"))
        throw std::invalid_argument("'requestUri': Unsupported scheme.");

    if (!requestUri.GetHost().has_value())
        throw std::invalid_argument("'requestUri': Host component is std::nullopt.");

    if (this->m_collections.contains(requestUri.GetHost().value()))
        this->m_collections.at(requestUri.GetHost().value()).Remove(cookie);
    
}

void CookieStorage::RemoveExpiredCookies() {
    for (auto& [_, collection] : this->m_collections) collection.RemoveExpired();
}

void CookieStorage::ClearCookies(const Uri& requestUri) {
    
    if (requestUri.IsRelativeUri())
        throw std::invalid_argument("'requestUri': Relative URI.");

    if ((requestUri.GetScheme() != "http") && (requestUri.GetScheme() != "https"))
        throw std::invalid_argument("'requestUri': Unsupported scheme.");

    if (!requestUri.GetHost().has_value())
        throw std::invalid_argument("'requestUri': Host component is std::nullopt.");

    if (this->m_collections.contains(requestUri.GetHost().value()))
        this->m_collections.at(requestUri.GetHost().value()).Clear();

}

void CookieStorage::ClearCookies() {
    for (auto& [_, collection] : this->m_collections) collection.Clear();
}