/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_SOCKET_H_
#define _VNETCORE_SOCKETS_SOCKET_H_

#include <Vnet/Exports.h>
#include <Vnet/Sockets/AddressFamily.h>
#include <Vnet/Sockets/SocketType.h>
#include <Vnet/Sockets/ProtocolType.h>
#include <Vnet/Sockets/ShutdownSocket.h>
#include <Vnet/Sockets/ISocketAddress.h>
#include <Vnet/Sockets/SocketFlags.h>
#include <Vnet/Sockets/PollEvent.h>

#include <cstdint>
#include <span>

namespace Vnet::Sockets {

#ifdef VNET_PLATFORM_WINDOWS
    typedef std::uint64_t NativeSocket_t;
    constexpr NativeSocket_t INVALID_SOCKET_HANDLE = (NativeSocket_t)(~0);
#else
    typedef std::int32_t NativeSocket_t;
    constexpr NativeSocket_t INVALID_SOCKET_HANDLE = -1;
#endif

    class VNETCOREAPI Socket {

    private:
        AddressFamily m_af;
        SocketType m_type;
        ProtocolType m_proto;
        NativeSocket_t m_socket;

    private:
        Socket(const NativeSocket_t socket, const AddressFamily af, const SocketType type, const ProtocolType proto);

    public:
        Socket(void);
        Socket(const AddressFamily af, const SocketType type, const ProtocolType proto);
        Socket(const Socket&) = delete;
        Socket(Socket&& socket) noexcept;
        virtual ~Socket(void);

        Socket& operator= (const Socket&) = delete;
        Socket& operator= (Socket&& socket) noexcept;
        bool operator== (const Socket& socket) const;

        AddressFamily GetAddressFamily(void) const;
		SocketType GetSocketType(void) const;
		ProtocolType GetProtocolType(void) const;
		NativeSocket_t GetNativeSocketHandle(void) const;

        void Close(void);
        void Shutdown(const ShutdownSocket how) const;

        void Bind(const ISocketAddress& sockaddr) const;
        void Connect(const ISocketAddress& sockaddr) const;

        void Listen(void) const;
        void Listen(const std::int32_t backlog) const;
        Socket Accept(void) const;

        std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const;
        std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;
        std::int32_t Send(const std::span<const std::uint8_t> data, const SocketFlags flags) const;
        std::int32_t Send(const std::span<const std::uint8_t> data) const;

        std::int32_t Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const;
        std::int32_t Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;
        std::int32_t Receive(const std::span<std::uint8_t> data, const SocketFlags flags) const;
        std::int32_t Receive(const std::span<std::uint8_t> data) const;

        std::int32_t SendTo(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags, const ISocketAddress& sockaddr) const;
        std::int32_t SendTo(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const ISocketAddress& sockaddr) const;
        std::int32_t SendTo(const std::span<const std::uint8_t> data, const SocketFlags flags, const ISocketAddress& sockaddr) const;
        std::int32_t SendTo(const std::span<const std::uint8_t> data, const ISocketAddress& sockaddr) const;

        std::int32_t ReceiveFrom(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags, ISocketAddress& sockaddr) const;
        std::int32_t ReceiveFrom(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, ISocketAddress& sockaddr) const;
        std::int32_t ReceiveFrom(const std::span<std::uint8_t> data, const SocketFlags flags, ISocketAddress& sockaddr) const;
        std::int32_t ReceiveFrom(const std::span<std::uint8_t> data, ISocketAddress& sockaddr) const;

        void GetSocketAddress(ISocketAddress& sockaddr) const;
        void GetPeerAddress(ISocketAddress& sockaddr) const;

        bool Poll(const PollEvent pollEvent, const std::int32_t timeout) const;
        std::int32_t GetAvailableBytes(void) const;

    };

}

#endif // _VNETCORE_SOCKETS_SOCKET_H_