/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Http/HttpException.h>

using namespace Vnet::Http;

HttpException::HttpException(const std::string& message)
    : HttpException(message, std::nullopt) { }

HttpException::HttpException(const std::string& message, const std::optional<HttpStatusCode>& statusCode)
    : std::runtime_error(message), m_statusCode(statusCode) { }

HttpException::HttpException(const HttpException& other) noexcept
    : std::runtime_error(other), m_statusCode(other.m_statusCode) { }

HttpException::HttpException(HttpException&& other) noexcept
    : std::runtime_error(std::move(other)), m_statusCode(std::move(other.m_statusCode)) { }

HttpException::~HttpException() { }

HttpException& HttpException::operator= (const HttpException& other) noexcept {
    
    if (this != &other) {
        std::runtime_error::operator= (other);
        this->m_statusCode = other.m_statusCode;
    }

    return static_cast<HttpException&>(*this);
}

HttpException& HttpException::operator= (HttpException&& other) noexcept {
    
    if (this != &other) {
        std::runtime_error::operator= (std::move(other));
        this->m_statusCode = std::move(other.m_statusCode);
    }

    return static_cast<HttpException&>(*this);
}

const std::optional<HttpStatusCode>& HttpException::GetStatusCode() const {
    return this->m_statusCode;
}