/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/BadUriException.h>

using namespace Vnet;

BadUriException::BadUriException()
    : BadUriException("URI malformed.") { }

BadUriException::BadUriException(const std::string& message)
    : std::runtime_error(message) { }

BadUriException::BadUriException(const BadUriException& other) noexcept
    : std::runtime_error(other) { }

BadUriException::BadUriException(BadUriException&& other) noexcept
    : std::runtime_error(std::move(other)) { }

BadUriException::~BadUriException() { }

BadUriException& BadUriException::operator= (const BadUriException& other) noexcept {
    if (this != &other) std::runtime_error::operator= (other);
    return static_cast<BadUriException&>(*this);
}

BadUriException& BadUriException::operator= (BadUriException&& other) noexcept {
    if (this != &other) std::runtime_error::operator= (std::move(other));
    return static_cast<BadUriException&>(*this);
}