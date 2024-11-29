/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_NATIVE_H_
#define _VNETCORE_SOCKETS_NATIVE_H_

#include <Vnet/Sockets/AddressFamily.h>
#include <Vnet/Sockets/SocketType.h>
#include <Vnet/Sockets/ProtocolType.h>
#include <Vnet/Sockets/ISocketAddress.h>
#include <Vnet/Sockets/SocketFlags.h>

#include <cstdint>
#include <unordered_map>

struct addrinfo;
struct sockaddr;

namespace Vnet::Sockets {

    class Native final {

    private:
        static std::unordered_map<AddressFamily, std::int32_t> s_addressFamilies;
        static std::unordered_map<SocketType, std::int32_t> s_socketTypes;
        static std::unordered_map<ProtocolType, std::int32_t> s_protocolTypes;
        static std::unordered_map<SocketFlags, std::int32_t> s_socketFlags;

    public:
        Native(void) = delete;

        static std::int32_t GetLastErrorCode(void) noexcept;

        static std::int32_t ToNativeAddressFamily(const AddressFamily af) noexcept;
        static std::int32_t ToNativeSocketType(const SocketType type) noexcept;
        static std::int32_t ToNativeProtocolType(const ProtocolType proto) noexcept;
        static std::int32_t ToNativeSocketFlags(const SocketFlags flags) noexcept;

        static struct addrinfo* CreateNativeAddrinfoFromISocketAddress(const ISocketAddress& sockaddr);
        static void NativeSockaddrToISocketAddress(const struct sockaddr* source, ISocketAddress& destination);

    };

}

#endif // _VNETCORE_SOCKETS_NATIVE_H_