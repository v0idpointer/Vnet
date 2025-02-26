/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Http/HttpParserException.h>

using namespace Vnet::Http;

HttpParserException::HttpParserException(const std::string& message)
    : HttpParserException(message, std::nullopt) { }

HttpParserException::HttpParserException(const std::string& message, const std::optional<HttpStatusCode>& statusCode)
    : HttpException(message, statusCode) { }

HttpParserException::HttpParserException(const HttpParserException& other) noexcept
    : HttpException(other) { }

HttpParserException::HttpParserException(HttpParserException&& other) noexcept
    : HttpException(std::move(other)) { }

HttpParserException::~HttpParserException() { }

HttpParserException& HttpParserException::operator= (const HttpParserException& other) noexcept {
    if (this != &other) HttpException::operator= (other);
    return static_cast<HttpParserException&>(*this);
}

HttpParserException& HttpParserException::operator= (HttpParserException&& other) noexcept {
    if (this != &other) HttpException::operator= (std::move(other));
    return static_cast<HttpParserException&>(*this);
}