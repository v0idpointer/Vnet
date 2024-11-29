/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/IpAddress.h>

#ifdef VNET_PLATFORM_WINDOWS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif

#include <regex>
#include <cstring>
#include <exception>
#include <stdexcept>

using namespace Vnet;
using namespace Vnet::Sockets;

static const std::regex s_ipv4Regex(R"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))");

IpAddress::IpAddress() : IpAddress(0, 0, 0, 0) { }

IpAddress::IpAddress(const std::uint8_t aa, const std::uint8_t bb, const std::uint8_t cc, const std::uint8_t dd) {
    this->m_bytes = { aa, bb, cc, dd };
}

IpAddress::IpAddress(const std::span<const std::uint8_t> bytes) {
    if (bytes.size() != 16) throw std::invalid_argument("The provided byte buffer does not contain a valid IPv6 address.");
    this->m_bytes = { bytes.begin(), bytes.end() };
}

IpAddress::IpAddress(const IpAddress& address) {
    this->operator= (address);
}

IpAddress::IpAddress(IpAddress&& address) noexcept {
    this->operator= (std::move(address));
}

IpAddress::~IpAddress() { }

IpAddress& IpAddress::operator= (const IpAddress& address) {
    if (this != &address) this->m_bytes = { address.m_bytes.begin(), address.m_bytes.end() };
    return static_cast<IpAddress&>(*this);
}

IpAddress& IpAddress::operator= (IpAddress&& address) noexcept {
    if (this != &address) this->m_bytes = std::move(address.m_bytes);
    return static_cast<IpAddress&>(*this);
}

bool IpAddress::operator== (const IpAddress& address) const {
    if (this->m_bytes.size() != address.m_bytes.size()) return false;
    return (std::memcmp(this->m_bytes.data(), address.m_bytes.data(), this->m_bytes.size()) == 0);
}

bool IpAddress::IsVersion6() const {
    return (this->m_bytes.size() == 16);
}

bool IpAddress::IsPublicAddress() const {
    return !this->IsPrivateAddress();
}

bool IpAddress::IsPrivateAddress() const {

    if (this->IsVersion6()) {
        
        if ((this->m_bytes[0] == 0xFC) || (this->m_bytes[0] == 0xFD)) return true;
        if ((this->m_bytes[0] == 0xFE) || (this->m_bytes[0] == 0x80)) return true;
        if (this->operator== (IpAddress::Localhost6())) return true;

        return false;
    }

    if (this->m_bytes[0] == 10) return true; // class A
    if ((this->m_bytes[0] == 172) && ((this->m_bytes[1] >= 16) && (this->m_bytes[1] < 32))) return true; // class B
    if ((this->m_bytes[0] == 192) && (this->m_bytes[1] == 168)) return true; // class c
    if ((this->m_bytes[0] == 169) && (this->m_bytes[1] == 254)) return true; // apipa
    if (this->operator== (IpAddress::Localhost())) return true; // loopback

    return false;
}

AddressFamily IpAddress::GetAddressFamily() const {
    if (this->IsVersion6()) return AddressFamily::IPV6;
    else return AddressFamily::IPV4;
}

std::string IpAddress::ToString() const {

    const bool isVersion6 = (this->m_bytes.size() == 16);
    if (isVersion6) {

        char addr[INET6_ADDRSTRLEN] = { 0 };
        inet_ntop(AF_INET6, this->m_bytes.data(), addr, INET6_ADDRSTRLEN);

        return addr;
    }
    else {

        char addr[INET_ADDRSTRLEN] = { 0 };
        inet_ntop(AF_INET, this->m_bytes.data(), addr, INET_ADDRSTRLEN);

        return addr;
    }

}

std::optional<IpAddress> IpAddress::ParseVersion4(const std::string_view address, const bool exceptions) {

    struct sockaddr_in sockaddr = { 0 };

    if (inet_pton(AF_INET, address.data(), &sockaddr.sin_addr) != 1) {
        if (exceptions) throw std::invalid_argument("The provided address is not a valid IPv4 address.");
        return std::nullopt;
    }

#ifdef VNET_PLATFORM_WINDOWS
    const std::uint32_t addr = sockaddr.sin_addr.S_un.S_addr;
#else
    const std::uint32_t addr = sockaddr.sin_addr.s_addr;
#endif

    return IpAddress(
        (addr & 0xFF), ((addr >> 8) & 0xFF), ((addr >> 16) & 0xFF), ((addr >> 24) & 0xFF)
    );
}

std::optional<IpAddress> IpAddress::ParseVersion6(const std::string_view address, const bool exceptions) {

    struct sockaddr_in6 sockaddr = { 0 };

    if (inet_pton(AF_INET6, address.data(), &sockaddr.sin6_addr) != 1) {
        if (exceptions) throw std::invalid_argument("The provided address is not a valid IPv6 address.");
        return std::nullopt;
    }

#ifdef VNET_PLATFORM_WINDOWS
    const std::uint8_t* bytes = sockaddr.sin6_addr.u.Byte;
#else
    const std::uint8_t* bytes = sockaddr.sin6_addr.s6_addr;
#endif

    return IpAddress(std::span<const std::uint8_t>(bytes, 16));
}

IpAddress IpAddress::Parse(const std::string_view address) {
    if (std::regex_match(address.data(), s_ipv4Regex)) return IpAddress::ParseVersion4(address, true).value();
    else return IpAddress::ParseVersion6(address, true).value();
}

std::optional<IpAddress> IpAddress::TryParse(const std::string_view address) {
    if (std::regex_match(address.data(), s_ipv4Regex)) return IpAddress::ParseVersion4(address, false);
    else return IpAddress::ParseVersion6(address, false);
}