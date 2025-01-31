/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/SystemNotSupportedException.h>

using namespace Vnet;

SystemNotSupportedException::SystemNotSupportedException()
    : SystemNotSupportedException("The requested feature is not supported on the current environment.") { }

SystemNotSupportedException::SystemNotSupportedException(const std::string& message)
    : std::runtime_error(message) { }

SystemNotSupportedException::SystemNotSupportedException(const SystemNotSupportedException& other) noexcept
    : std::runtime_error(other) { }

SystemNotSupportedException::SystemNotSupportedException(SystemNotSupportedException&& other) noexcept
    : std::runtime_error(std::move(other)) { }

SystemNotSupportedException::~SystemNotSupportedException() { }

SystemNotSupportedException& SystemNotSupportedException::operator= (const SystemNotSupportedException& other) noexcept {
    if (this != &other) std::runtime_error::operator= (other);
    return static_cast<SystemNotSupportedException&>(*this);
}

SystemNotSupportedException& SystemNotSupportedException::operator= (SystemNotSupportedException&& other) noexcept {
    if (this != &other) std::runtime_error::operator= (std::move(other));
    return static_cast<SystemNotSupportedException&>(*this);
}