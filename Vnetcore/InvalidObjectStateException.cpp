/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/InvalidObjectStateException.h>

using namespace Vnet;

InvalidObjectStateException::InvalidObjectStateException()
    : InvalidObjectStateException("The object is in an invalid state.") { }

InvalidObjectStateException::InvalidObjectStateException(const std::string& message)
    : std::runtime_error(message) { }

InvalidObjectStateException::InvalidObjectStateException(const InvalidObjectStateException& other) noexcept
    : std::runtime_error(other) { }

InvalidObjectStateException::InvalidObjectStateException(InvalidObjectStateException&& other) noexcept
    : std::runtime_error(std::move(other)) { }

InvalidObjectStateException::~InvalidObjectStateException() { }

InvalidObjectStateException& InvalidObjectStateException::operator= (const InvalidObjectStateException& other) noexcept {
    if (this != &other) std::runtime_error::operator= (other);
    return static_cast<InvalidObjectStateException&>(*this);
}

InvalidObjectStateException& InvalidObjectStateException::operator= (InvalidObjectStateException&& other) noexcept {
    if (this != &other) std::runtime_error::operator= (std::move(other));
    return static_cast<InvalidObjectStateException&>(*this);
}