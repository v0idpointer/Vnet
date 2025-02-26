/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Net/NetworkException.h>

using namespace Vnet::Net;

NetworkException::NetworkException(const std::string& message)
    : std::runtime_error(message) { }

NetworkException::NetworkException(const NetworkException& other) noexcept
    : std::runtime_error(other) { }

NetworkException::NetworkException(NetworkException&& other) noexcept 
    : std::runtime_error(std::move(other)) { }

NetworkException::~NetworkException() { }

NetworkException& NetworkException::operator= (const NetworkException& other) noexcept {
    if (this != &other) std::runtime_error::operator= (other);
    return static_cast<NetworkException&>(*this);
}

NetworkException& NetworkException::operator= (NetworkException&& other) noexcept {
    if (this != &other) std::runtime_error::operator= (std::move(other));
    return static_cast<NetworkException&>(*this);
}