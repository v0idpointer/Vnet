/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include "SocketsApi.h"
#include "Sockets/Native.h"

#include <Vnet/Platform.h>
#include <Vnet/Sockets/Socket.h>
#include <Vnet/Sockets/SocketException.h>
#include <Vnet/Sockets/IpSocketAddress.h>

using namespace Vnet;
using namespace Vnet::Sockets;

std::unordered_map<AddressFamily, std::int32_t> Native::s_addressFamilies = { 

    { AddressFamily::UNSPECIFIED, NULL },
    { AddressFamily::IPV4, AF_INET },
    { AddressFamily::IPV6, AF_INET6 },

};

std::unordered_map<SocketType, std::int32_t> Native::s_socketTypes = { 

    { SocketType::STREAM, SOCK_STREAM },
    { SocketType::DATAGRAM, SOCK_DGRAM },
    { SocketType::RAW, SOCK_RAW },
    { SocketType::RDM, SOCK_RDM },
    { SocketType::SEQPACKET, SOCK_SEQPACKET },

};

std::unordered_map<ProtocolType, std::int32_t> Native::s_protocolTypes = { 

    { ProtocolType::UNSPECIFIED, NULL },
    { ProtocolType::TCP, IPPROTO_TCP },
    { ProtocolType::UDP, IPPROTO_UDP },

};

std::unordered_map<SocketFlags, std::int32_t> Native::s_socketFlags = { 

    { SocketFlags::NONE, 0 },
    { SocketFlags::OUT_OF_BAND, MSG_OOB },
    { SocketFlags::PEEK, MSG_PEEK },
    { SocketFlags::DONT_ROUTE, MSG_DONTROUTE },
    { SocketFlags::TRUNCATED, MSG_TRUNC },
    { SocketFlags::CONTROL_DATA_TRUNCATED, MSG_CTRUNC },
    { SocketFlags::WAIT_ALL, MSG_WAITALL },

};

std::int32_t Native::GetLastErrorCode() noexcept {

#ifdef VNET_PLATFORM_WINDOWS
    return WSAGetLastError();
#else
    return errno;
#endif

}

std::int32_t Native::ToNativeAddressFamily(const AddressFamily af) noexcept {
    if (Native::s_addressFamilies.contains(af)) return Native::s_addressFamilies.at(af);
    else return static_cast<std::int32_t>(INVALID_SOCKET_HANDLE);
}

std::int32_t Native::ToNativeSocketType(const SocketType type) noexcept {
    if (Native::s_socketTypes.contains(type)) return Native::s_socketTypes.at(type);
    else return static_cast<std::int32_t>(INVALID_SOCKET_HANDLE);
}

std::int32_t Native::ToNativeProtocolType(const ProtocolType proto) noexcept {
    if (Native::s_protocolTypes.contains(proto)) return Native::s_protocolTypes.at(proto);
    else return static_cast<std::int32_t>(INVALID_SOCKET_HANDLE);
}

std::int32_t Native::ToNativeSocketFlags(const SocketFlags flags) noexcept {
    
    std::int32_t nf = 0;
    for (const auto& [k, v] : Native::s_socketFlags) {
        if (static_cast<bool>(k & flags)) nf |= v;
    }

    return nf;
}

IpAddress Native::ToIpAddress4(const struct sockaddr_in* const sockaddr) noexcept {

#ifdef VNET_PLATFORM_WINDOWS
    const std::uint32_t addr = sockaddr->sin_addr.S_un.S_addr;
#else
    const std::uint32_t addr = sockaddr->sin_addr.s_addr;
#endif

    return IpAddress(
        (addr & 0xFF), ((addr >> 8) & 0xFF), ((addr >> 16) & 0xFF), ((addr >> 24) & 0xFF)
    );
}

IpAddress Native::ToIpAddress6(const struct sockaddr_in6* const sockaddr) noexcept {

#ifdef VNET_PLATFORM_WINDOWS
    const std::uint8_t* bytes = sockaddr->sin6_addr.u.Byte;
#else
    const std::uint8_t* bytes = sockaddr->sin6_addr.s6_addr;
#endif

    return IpAddress(std::span<const std::uint8_t>(bytes, 16));
}

struct addrinfo* Native::CreateNativeAddrinfoFromISocketAddress(const ISocketAddress& sockaddr) {

    // ISocketAddress for IPv4 and IPv6
    if (const IpSocketAddress* pIpSockaddr = dynamic_cast<const IpSocketAddress*>(&sockaddr)) {
        
        struct addrinfo* result = nullptr;
        std::int32_t res = getaddrinfo(
            pIpSockaddr->GetIpAddress().ToString().c_str(),
            std::to_string(pIpSockaddr->GetPort()).c_str(),
            nullptr,
            &result
        );

        if (res == INVALID_SOCKET_HANDLE)
            throw SocketException(Native::GetLastErrorCode());

        return result;
    }

    throw std::invalid_argument("Unknown ISocketAddress implementation.");
}

static inline std::uint16_t SwapEndianness(const std::uint16_t val) noexcept {
    return (((val & 0xFF) << 8) | ((val & 0xFF00) >> 8));
}

void Native::NativeSockaddrToISocketAddress(const struct sockaddr* source, ISocketAddress& destination) {

    // ISocketAddress for IPv4 and IPv6
    if (IpSocketAddress* pIpSockaddr = dynamic_cast<IpSocketAddress*>(&destination)) {
        
        if (source->sa_family == AF_INET) {
            const struct sockaddr_in* pSockaddr = reinterpret_cast<const struct sockaddr_in*>(source);
            pIpSockaddr->SetIpAddress(Native::ToIpAddress4(pSockaddr));
            pIpSockaddr->SetPort(SwapEndianness(pSockaddr->sin_port));
        }
        else {
            const struct sockaddr_in6* pSockaddr = reinterpret_cast<const struct sockaddr_in6*>(source);
            pIpSockaddr->SetIpAddress(Native::ToIpAddress6(pSockaddr));
            pIpSockaddr->SetPort(SwapEndianness(pSockaddr->sin6_port));
        }

        return;
    }

    throw std::invalid_argument("Unknown ISocketAddress implementation.");
}