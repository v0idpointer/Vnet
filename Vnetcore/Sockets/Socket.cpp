/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Sockets/Socket.h>
#include <Vnet/Sockets/SocketException.h>

#include "SocketsApi.h"
#include "Sockets/Native.h"

using namespace Vnet::Sockets;

Socket::Socket(const NativeSocket_t socket, const AddressFamily af, const SocketType type, const Protocol proto)
    : m_socket(socket), m_af(af), m_type(type), m_proto(proto) { }

Socket::Socket() 
    : Socket(INVALID_SOCKET_HANDLE, static_cast<AddressFamily>(-1), static_cast<SocketType>(-1), static_cast<Protocol>(-1)) { }

Socket::Socket(const AddressFamily af, const SocketType type, const Protocol proto)
    : Socket(INVALID_SOCKET_HANDLE, af, type, proto) {

    std::int32_t addressFamily = Native::ToNativeAddressFamily(af);
    std::int32_t socketType = Native::ToNativeSocketType(type);
    std::int32_t protocol = Native::ToNativeProtocol(proto);

    this->m_socket = socket(addressFamily, socketType, protocol);
    if (this->m_socket == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

}

Socket::Socket(Socket&& socket) noexcept {
    this->m_socket = INVALID_SOCKET_HANDLE;
    this->operator= (std::move(socket));
}

Socket::~Socket() {
    if (this->m_socket != INVALID_SOCKET_HANDLE) this->Close();
}

Socket& Socket::operator= (Socket&& socket) noexcept {

    if (this != &socket) {

        if (this->m_socket != INVALID_SOCKET_HANDLE) this->Close();

        this->m_af = socket.m_af;
        this->m_type = socket.m_type;
        this->m_proto = socket.m_proto;
        this->m_socket = socket.m_socket;
        socket.m_socket = INVALID_SOCKET_HANDLE;

    }

    return static_cast<Socket&>(*this);
}

bool Socket::operator== (const Socket& socket) const {
    return (this->m_socket == socket.m_socket);
}

AddressFamily Socket::GetAddressFamily() const {
    return this->m_af;
}

SocketType Socket::GetSocketType() const {
    return this->m_type;
}

Protocol Socket::GetProtocol() const {
    return this->m_proto;
}

NativeSocket_t Socket::GetNativeSocketHandle() const {
    return this->m_socket;
}

void Socket::Close() {

#ifdef VNET_PLATFORM_WINDOWS
    int (*pfnClosesocket)(NativeSocket_t) = &closesocket;
#else
    int (*pfnClosesocket)(NativeSocket_t) = &close;
#endif

    if (pfnClosesocket(this->m_socket) == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

    this->m_socket = INVALID_SOCKET_HANDLE;

}

void Socket::Shutdown(const ShutdownSocket how) const {

    std::int32_t sd = 0;
    switch (how) {

    case ShutdownSocket::RECEIVE:
        sd = SD_RECEIVE;
        break;

    case ShutdownSocket::SEND:
        sd = SD_SEND;
        break;

    case ShutdownSocket::BOTH:
        sd = SD_BOTH;
        break;

    default:
        throw std::invalid_argument("'how': Invalid shutdown method.");
        break;

    }

    if (shutdown(this->m_socket, sd) == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

}

void Socket::Bind(const ISocketAddress& sockaddr) const {
    
    struct addrinfo* result = nullptr;
    try { result = Native::CreateNativeAddrinfoFromISocketAddress(sockaddr); }
    catch (const std::invalid_argument& ex) {
        using namespace std::string_literals;
        throw std::invalid_argument("'sockaddr': "s + ex.what());
    }
    
    if (bind(this->m_socket, result->ai_addr, static_cast<std::int32_t>(result->ai_addrlen)) == INVALID_SOCKET_HANDLE) {
        freeaddrinfo(result);
        throw SocketException(Native::GetLastErrorCode());
    }

    freeaddrinfo(result);

}

void Socket::Connect(const ISocketAddress& sockaddr) const {
    
    struct addrinfo* result = nullptr;
    try { result = Native::CreateNativeAddrinfoFromISocketAddress(sockaddr); }
    catch (const std::invalid_argument& ex) {
        using namespace std::string_literals;
        throw std::invalid_argument("'sockaddr': "s + ex.what());
    }
    
    if (connect(this->m_socket, result->ai_addr, static_cast<std::int32_t>(result->ai_addrlen)) == INVALID_SOCKET_HANDLE) {
        freeaddrinfo(result);
        throw SocketException(Native::GetLastErrorCode());
    }

    freeaddrinfo(result);

}

void Socket::Listen() const {
    this->Listen(SOMAXCONN);
}

void Socket::Listen(const std::int32_t backlog) const {

    if (listen(this->m_socket, backlog) == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

}

Socket Socket::Accept() const {
    
    NativeSocket_t client = accept(this->m_socket, nullptr, nullptr);
    if (client == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

    return Socket(client, this->GetAddressFamily(), this->GetSocketType(), this->GetProtocol());
}

std::int32_t Socket::Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const {
    
    if (offset < 0) throw std::out_of_range("'offset' is less than zero.");
    if (offset > data.size()) throw std::out_of_range("'offset' is greater than the buffer size.");
    if (size < 0) throw std::out_of_range("'size' is less than zero.");
    if (size > (data.size() - offset)) throw std::out_of_range("'size' is greater than the buffer size minus 'offset'.");

    const char* const buffer = reinterpret_cast<const char*>(data.data() + offset);

    std::int32_t sent = send(this->m_socket, buffer, size, Native::ToNativeSocketFlags(flags));
    if (sent == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

    return sent;
}

std::int32_t Socket::Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {
    return this->Send(data, offset, size, SocketFlags::NONE);
}

std::int32_t Socket::Send(const std::span<const std::uint8_t> data, const SocketFlags flags) const {
    return this->Send(data, 0, data.size(), flags);
}

std::int32_t Socket::Send(const std::span<const std::uint8_t> data) const {
    return this->Send(data, 0, data.size(), SocketFlags::NONE);
}

std::int32_t Socket::Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const {

    if (offset < 0) throw std::out_of_range("'offset' is less than zero.");
    if (offset > data.size()) throw std::out_of_range("'offset' is greater than the buffer size.");
    if (size < 0) throw std::out_of_range("'size' is less than zero.");
    if (size > (data.size() - offset)) throw std::out_of_range("'size' is greater than the buffer size minus 'offset'.");

    char* const buffer = reinterpret_cast<char*>(data.data() + offset);

    std::int32_t read = recv(this->m_socket, buffer, size, Native::ToNativeSocketFlags(flags));
    if (read == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

    return read;
}

std::int32_t Socket::Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {
    return this->Receive(data, offset, size, SocketFlags::NONE);
}

std::int32_t Socket::Receive(const std::span<std::uint8_t> data, const SocketFlags flags) const {
    return this->Receive(data, 0, data.size(), flags);
}

std::int32_t Socket::Receive(const std::span<std::uint8_t> data) const {
    return this->Receive(data, 0, data.size(), SocketFlags::NONE);
}

std::int32_t Socket::SendTo(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags, const ISocketAddress& sockaddr) const {

    if (offset < 0) throw std::out_of_range("'offset' is less than zero.");
    if (offset > data.size()) throw std::out_of_range("'offset' is greater than the buffer size.");
    if (size < 0) throw std::out_of_range("'size' is less than zero.");
    if (size > (data.size() - offset)) throw std::out_of_range("'size' is greater than the buffer size minus 'offset'.");

    const char* const buffer = reinterpret_cast<const char*>(data.data() + offset);
    struct addrinfo* result = nullptr;
    try { result = Native::CreateNativeAddrinfoFromISocketAddress(sockaddr); }
    catch (const std::invalid_argument& ex) {
        using namespace std::string_literals;
        throw std::invalid_argument("'sockaddr': "s + ex.what());
    }

    std::int32_t sent = sendto(this->m_socket, buffer, size, Native::ToNativeSocketFlags(flags), result->ai_addr, static_cast<std::int32_t>(result->ai_addrlen));
    if (sent == INVALID_SOCKET_HANDLE) {
        freeaddrinfo(result);
        throw SocketException(Native::GetLastErrorCode());
    }

    freeaddrinfo(result);

    return sent;
}

std::int32_t Socket::SendTo(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const ISocketAddress& sockaddr) const {
    return this->SendTo(data, offset, size, SocketFlags::NONE, sockaddr);
}

std::int32_t Socket::SendTo(const std::span<const std::uint8_t> data, const SocketFlags flags, const ISocketAddress& sockaddr) const {
    return this->SendTo(data, 0, data.size(), flags, sockaddr);
}

std::int32_t Socket::SendTo(const std::span<const std::uint8_t> data, const ISocketAddress& sockaddr) const {
    return this->SendTo(data, 0, data.size(), SocketFlags::NONE, sockaddr);
}

std::int32_t Socket::ReceiveFrom(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags, ISocketAddress& sockaddr) const {

    if (offset < 0) throw std::out_of_range("'offset' is less than zero.");
    if (offset > data.size()) throw std::out_of_range("'offset' is greater than the buffer size.");
    if (size < 0) throw std::out_of_range("'size' is less than zero.");
    if (size > (data.size() - offset)) throw std::out_of_range("'size' is greater than the buffer size minus 'offset'.");

    struct sockaddr sender;
    socklen_t senderLen = sizeof(sender);
    char* const buffer = reinterpret_cast<char*>(data.data() + offset);

    std::int32_t read = recvfrom(this->m_socket, buffer, size, Native::ToNativeSocketFlags(flags), &sender, &senderLen);
    if (read == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

    try { Native::NativeSockaddrToISocketAddress(&sender, sockaddr); }
    catch (const std::invalid_argument& ex) {
        using namespace std::string_literals;
        throw std::invalid_argument("'sockaddr': "s + ex.what());
    }

    return read;
}

std::int32_t Socket::ReceiveFrom(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, ISocketAddress& sockaddr) const {
    return this->ReceiveFrom(data, offset, size, SocketFlags::NONE, sockaddr);
}

std::int32_t Socket::ReceiveFrom(const std::span<std::uint8_t> data, const SocketFlags flags, ISocketAddress& sockaddr) const {
    return this->ReceiveFrom(data, 0, data.size(), sockaddr);
}

std::int32_t Socket::ReceiveFrom(const std::span<std::uint8_t> data, ISocketAddress& sockaddr) const {
    return this->ReceiveFrom(data, 0, data.size(), SocketFlags::NONE, sockaddr);
}

void Socket::GetSocketAddress(ISocketAddress& sockaddr) const {

    struct sockaddr sockName;
    socklen_t sockNameLen = sizeof(sockName);

    if (getsockname(this->m_socket, &sockName, &sockNameLen) == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

    try { Native::NativeSockaddrToISocketAddress(&sockName, sockaddr); }
    catch (const std::invalid_argument& ex) {
        using namespace std::string_literals;
        throw std::invalid_argument("'sockaddr': "s + ex.what());
    }

}

void Socket::GetPeerAddress(ISocketAddress& sockaddr) const {

    struct sockaddr peerName;
    socklen_t peerNameLen = sizeof(peerName);

    if (getpeername(this->m_socket, &peerName, &peerNameLen))
        throw SocketException(Native::GetLastErrorCode());

    try { Native::NativeSockaddrToISocketAddress(&peerName, sockaddr); }
    catch (const std::invalid_argument& ex) {
        using namespace std::string_literals;
        throw std::invalid_argument("'sockaddr': "s + ex.what());
    }

}

bool Socket::Poll(const PollEvent pollEvent, const std::int32_t timeout) const {

    std::int32_t event = 0;
    switch (pollEvent) {

    case PollEvent::READ:
        event = POLLIN;
        break;

    case PollEvent::WRITE:
        event = POLLOUT;
        break;
    case PollEvent::ERROR:
        event = POLLERR;
        break;

    default:
        throw std::invalid_argument("'pollEvent': Invalid event.");
        break;

    }

#ifdef VNET_PLATFORM_WINDOWS

    WSAPOLLFD fd = { 0 };
    fd.fd = this->m_socket;
    fd.events = event;

    std::int32_t result = WSAPoll(&fd, 1, timeout);
    if (result == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

    return (result > 0);
    
#else

    std::int32_t epollFd = epoll_create1(0);
    if (epollFd == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

    struct epoll_event fd = { 0 };
    fd.data.fd = this->m_socket;
    fd.events = event;

    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, this->m_socket, &fd) == INVALID_SOCKET_HANDLE) {
        close(epollFd);
        throw SocketException(Native::GetLastErrorCode());
    }

    struct epoll_event events[1];
    std::int32_t result = epoll_wait(epollFd, events, 1, timeout);
    if (result == INVALID_SOCKET_HANDLE) {
        close(epollFd);
        throw SocketException(Native::GetLastErrorCode());
    }

    close(epollFd);

    return (result > 0);

#endif

}

std::int32_t Socket::GetAvailableBytes() const {

#ifdef VNET_PLATFORM_WINDOWS

    u_long argp = 0;
    if (ioctlsocket(this->m_socket, FIONREAD, &argp) == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

    return static_cast<std::int32_t>(argp);

#else

    std::int32_t argp = 0;
    if (ioctl(this->m_socket, FIONREAD, &argp) == INVALID_SOCKET_HANDLE)
        throw SocketException(Native::GetLastErrorCode());

    return argp;

#endif

};