/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/Sockets/SocketException.h>

#ifdef VNET_PLATFORM_WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#else
#include <cstring>
#endif

using namespace Vnet::Sockets;

SocketException::SocketException(const std::int32_t errorCode)
    : SocketException(errorCode, SocketException::GetMessageFromErrorCode(errorCode)) { }

SocketException::SocketException(const std::int32_t errorCode, const std::string& message)
    : std::runtime_error(message), m_errorCode(errorCode) { }

SocketException::SocketException(const SocketException& other) noexcept
    : std::runtime_error(other), m_errorCode(other.m_errorCode) { }

SocketException::SocketException(SocketException&& other) noexcept
    : std::runtime_error(std::move(other)), m_errorCode(other.m_errorCode) {
    other.m_errorCode = 0;
}

SocketException::~SocketException() { }

SocketException& SocketException::operator= (const SocketException& other) noexcept {

    if (this != &other) {
        std::runtime_error::operator= (other);
        this->m_errorCode = other.m_errorCode;
    }

    return static_cast<SocketException&>(*this);
}

SocketException& SocketException::operator= (SocketException&& other) noexcept {

    if (this != &other) {
        std::runtime_error::operator= (std::move(other));
        this->m_errorCode = other.m_errorCode;
        other.m_errorCode = 0;
    }

    return static_cast<SocketException&>(*this);
}

std::int32_t SocketException::GetErrorCode() const {
    return this->m_errorCode;
}

std::string SocketException::GetMessageFromErrorCode(const std::int32_t errorCode) {

#ifdef VNET_PLATFORM_WINDOWS

    LPSTR pszMessage = NULL;

	FormatMessageA(
		(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS),
		NULL,
		errorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		reinterpret_cast<LPSTR>(&pszMessage),
		NULL,
		NULL
	);

    const std::string str = { pszMessage };
	LocalFree(pszMessage);
	pszMessage = NULL;

    return str;
#else
    return strerror(errorCode);
#endif

}