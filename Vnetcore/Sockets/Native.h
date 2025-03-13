/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_NATIVE_H_
#define _VNETCORE_SOCKETS_NATIVE_H_

#include <Vnet/IpAddress.h>
#include <Vnet/Sockets/AddressFamily.h>
#include <Vnet/Sockets/SocketType.h>
#include <Vnet/Sockets/Protocol.h>
#include <Vnet/Sockets/ISocketAddress.h>
#include <Vnet/Sockets/SocketFlags.h>
#include <Vnet/Sockets/SocketOption.h>
#include <Vnet/Sockets/SocketOptionLevel.h>

#include <cstdint>
#include <unordered_map>

struct addrinfo;
struct sockaddr;
struct sockaddr_in;
struct sockaddr_in6;

namespace Vnet::Sockets {

    class Native final {

    private:
        static std::unordered_map<AddressFamily, std::int32_t> s_addressFamilies;
        static std::unordered_map<SocketType, std::int32_t> s_socketTypes;
        static std::unordered_map<Protocol, std::int32_t> s_protocols;
        static std::unordered_map<SocketFlags, std::int32_t> s_socketFlags;
        static std::unordered_map<SocketOptionLevel, std::int32_t> s_optionLevels;
        static std::unordered_map<SocketOption, std::pair<std::int32_t, SocketOptionLevel>> s_options;

    public:
        Native(void) = delete;

        static std::int32_t GetLastErrorCode(void) noexcept;

        static std::optional<std::int32_t> ToNativeAddressFamily(const AddressFamily af) noexcept;
        static std::optional<std::int32_t> ToNativeSocketType(const SocketType type) noexcept;
        static std::optional<std::int32_t> ToNativeProtocol(const Protocol proto) noexcept;
        static std::optional<std::int32_t> ToNativeSocketFlags(const SocketFlags flags) noexcept;
        static std::optional<std::int32_t> ToNativeSocketOptionLevel(const SocketOptionLevel level) noexcept;
        static std::optional<std::int32_t> ToNativeSocketOption(const SocketOptionLevel level, const SocketOption option) noexcept;

        static IpAddress ToIpAddress4(const struct sockaddr_in* const sockaddr) noexcept;
        static IpAddress ToIpAddress6(const struct sockaddr_in6* const sockaddr) noexcept;

        static struct addrinfo* CreateNativeAddrinfoFromISocketAddress(const ISocketAddress& sockaddr);
        static void NativeSockaddrToISocketAddress(const struct sockaddr* source, ISocketAddress& destination);

    };

}

#endif // _VNETCORE_SOCKETS_NATIVE_H_