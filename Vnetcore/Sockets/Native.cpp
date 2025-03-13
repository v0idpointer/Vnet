/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
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

std::unordered_map<Protocol, std::int32_t> Native::s_protocols = { 

    { Protocol::UNSPECIFIED, NULL },
    { Protocol::TCP, IPPROTO_TCP },
    { Protocol::UDP, IPPROTO_UDP },

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

std::unordered_map<SocketOptionLevel, std::int32_t> Native::s_optionLevels = {

    { SocketOptionLevel::SOCKET, SOL_SOCKET },

};

std::unordered_map<SocketOption, std::pair<std::int32_t, SocketOptionLevel>> Native::s_options = { 

    { SocketOption::DEBUG, { SO_DEBUG, SocketOptionLevel::SOCKET } },
    { SocketOption::BROADCAST, { SO_BROADCAST, SocketOptionLevel::SOCKET } },
    { SocketOption::REUSE_ADDRESS, { SO_REUSEADDR, SocketOptionLevel::SOCKET } },
    { SocketOption::KEEP_ALIVE, { SO_KEEPALIVE, SocketOptionLevel::SOCKET } },
    { SocketOption::LINGER, { SO_LINGER, SocketOptionLevel::SOCKET } },
    { SocketOption::OUT_OF_BAND_INLINE, { SO_OOBINLINE, SocketOptionLevel::SOCKET } },
    { SocketOption::SEND_BUFFER_SIZE, { SO_SNDBUF, SocketOptionLevel::SOCKET } },
    { SocketOption::RECEIVE_BUFFER_SIZE, { SO_RCVBUF, SocketOptionLevel::SOCKET } },
    { SocketOption::DONT_ROUTE, { SO_DONTROUTE, SocketOptionLevel::SOCKET } },
    { SocketOption::RECEIVE_LOW_WATERMARK, { SO_RCVLOWAT, SocketOptionLevel::SOCKET } },
    { SocketOption::RECEIVE_TIMEOUT, { SO_RCVTIMEO, SocketOptionLevel::SOCKET } },
    { SocketOption::SEND_LOW_WATERMARK, { SO_SNDLOWAT, SocketOptionLevel::SOCKET } },
    { SocketOption::SEND_TIMEOUT, { SO_SNDTIMEO, SocketOptionLevel::SOCKET } },

};

std::int32_t Native::GetLastErrorCode() noexcept {

#ifdef VNET_PLATFORM_WINDOWS
    return WSAGetLastError();
#else
    return errno;
#endif

}

std::optional<std::int32_t> Native::ToNativeAddressFamily(const AddressFamily af) noexcept {
    if (Native::s_addressFamilies.contains(af)) return Native::s_addressFamilies.at(af);
    else return std::nullopt;
}

std::optional<std::int32_t> Native::ToNativeSocketType(const SocketType type) noexcept {
    if (Native::s_socketTypes.contains(type)) return Native::s_socketTypes.at(type);
    else return std::nullopt;
}

std::optional<std::int32_t> Native::ToNativeProtocol(const Protocol proto) noexcept {
    if (Native::s_protocols.contains(proto)) return Native::s_protocols.at(proto);
    else return std::nullopt;
}

std::optional<std::int32_t> Native::ToNativeSocketFlags(const SocketFlags flags) noexcept {

    std::int32_t bit = 1;
    std::int32_t nativeFlags = 0;
    std::int32_t i = static_cast<std::int32_t>(flags);

    while (i > 0) {

        if (i & 1) {

            const SocketFlags flag = static_cast<SocketFlags>(bit);
            if (!Native::s_socketFlags.contains(flag)) return std::nullopt;

            nativeFlags |= Native::s_socketFlags.at(flag);

        }

        i >>= 1;
        bit <<= 1;

    }

    return nativeFlags;
}

std::optional<std::int32_t> Native::ToNativeSocketOptionLevel(const SocketOptionLevel level) noexcept {
    if (Native::s_optionLevels.contains(level)) return Native::s_optionLevels.at(level);
    else return std::nullopt;
}

std::optional<std::int32_t> Native::ToNativeSocketOption(const SocketOptionLevel level, const SocketOption option) noexcept {

    if (!Native::s_options.contains(option)) return std::nullopt;
    const auto& [opt, lvl] = Native::s_options.at(option);

    if (lvl == level) return opt;
    else return std::nullopt;
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