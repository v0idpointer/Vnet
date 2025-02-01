/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/Security/SecurityException.h>

#include <openssl/err.h>

using namespace Vnet::Security;

SecurityException::SecurityException(const ErrorCode_t errorCode)
    : SecurityException(errorCode, SecurityException::GetMessageFromErrorCode(errorCode)) { }

SecurityException::SecurityException(const ErrorCode_t errorCode, const std::string& message)
    : std::runtime_error(message), m_errorCode(errorCode) { }

SecurityException::SecurityException(const SecurityException& other) noexcept 
    : std::runtime_error(other), m_errorCode(other.m_errorCode) { }

SecurityException::SecurityException(SecurityException&& other) noexcept 
    : std::runtime_error(std::move(other)), m_errorCode(other.m_errorCode) {
    other.m_errorCode = 0;
}

SecurityException::~SecurityException() { }

SecurityException& SecurityException::operator= (const SecurityException& other) noexcept {

    if (this != &other) {
        std::runtime_error::operator= (other);
        this->m_errorCode = other.m_errorCode;
    }

    return static_cast<SecurityException&>(*this);
}

SecurityException& SecurityException::operator= (SecurityException&& other) noexcept {

    if (this != &other) {
        std::runtime_error::operator= (std::move(other));
        this->m_errorCode = other.m_errorCode;
        other.m_errorCode = 0;
    }

    return static_cast<SecurityException&>(*this);
}

ErrorCode_t SecurityException::GetErrorCode() const {
    return this->m_errorCode;
}

std::string SecurityException::GetMessageFromErrorCode(const ErrorCode_t errorCode) {
    
    char buffer[512];
    ERR_error_string_n(errorCode, buffer, sizeof(buffer));

    return std::string(buffer);
}