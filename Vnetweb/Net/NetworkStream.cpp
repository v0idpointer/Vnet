/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Net/NetworkStream.h>
#include <Vnet/InvalidObjectStateException.h>

#include <exception>
#include <stdexcept>

using namespace Vnet;
using namespace Vnet::Net;
using namespace Vnet::Security;
using namespace Vnet::Sockets;

NetworkStream::NetworkStream(std::shared_ptr<Socket> socket, std::shared_ptr<SecureConnection> ssl) { 

    if (socket == nullptr)
        throw std::invalid_argument("'socket': nullptr");

    this->m_socket = std::move(socket);
    this->m_ssl = std::move(ssl);

}

NetworkStream::NetworkStream(const NetworkStream& stream) {
    this->operator= (stream);
}

NetworkStream::NetworkStream(NetworkStream&& stream) noexcept {
    this->operator= (std::move(stream));
}

NetworkStream::~NetworkStream() { }

NetworkStream& NetworkStream::operator= (const NetworkStream& stream) {

    if (this != &stream) {
        this->m_socket = stream.m_socket;
        this->m_ssl = stream.m_ssl;
    }

    return static_cast<NetworkStream&>(*this);
}

NetworkStream& NetworkStream::operator= (NetworkStream&& stream) noexcept {

    if (this != &stream) {
        this->m_socket = std::move(stream.m_socket);
        this->m_ssl = std::move(stream.m_ssl);
    }

    return static_cast<NetworkStream&>(*this);
}

std::shared_ptr<Socket> NetworkStream::GetSocket() const {
    return this->m_socket;
}

std::shared_ptr<SecureConnection> NetworkStream::GetSecureConnection() const {
    return this->m_ssl;
}

std::int32_t NetworkStream::GetAvailableBytes() const {

    try {

        if (this->m_ssl) {

            bool blocking = this->m_socket->IsBlocking();
            this->m_socket->SetBlocking(false);
    
            const std::int32_t available = this->m_ssl->GetAvailableBytes();
            this->m_socket->SetBlocking(blocking);
    
            return available;
        }
        
        return this->m_socket->GetAvailableBytes();

    }
    catch (const InvalidObjectStateException&) {
        throw InvalidObjectStateException("The underlying Socket and/or SecureConnection objects are closed.");
    }

}

std::int32_t NetworkStream::Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const {

    if (flags != SocketFlags::NONE)
        throw std::invalid_argument("'flags': This value must be SocketFlags::NONE.");

    try {
        if (this->m_ssl) return this->m_ssl->Send(data, offset, size, flags);
        else return this->m_socket->Send(data, offset, size, flags);
    }
    catch (const InvalidObjectStateException&) {
        throw InvalidObjectStateException("The underlying Socket and/or SecureConnection objects are closed.");
    }

}

std::int32_t NetworkStream::Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {
    return NetworkStream::Send(data, offset, size, SocketFlags::NONE);
}

std::int32_t NetworkStream::Send(const std::span<const std::uint8_t> data, const SocketFlags flags) const {
    return NetworkStream::Send(data, 0, data.size(), flags);
}

std::int32_t NetworkStream::Send(const std::span<const std::uint8_t> data) const {
    return NetworkStream::Send(data, 0, data.size(), SocketFlags::NONE);
}

std::int32_t NetworkStream::Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const {

    if ((flags != SocketFlags::NONE) && (flags != SocketFlags::PEEK))
        throw std::invalid_argument("'flags': This value must be SocketFlags::NONE or SocketFlags::PEEK.");

    try {
        if (this->m_ssl) return this->m_ssl->Receive(data, offset, size, flags);
        else return this->m_socket->Receive(data, offset, size, flags);
    }
    catch (const InvalidObjectStateException&) {
        throw InvalidObjectStateException("The underlying Socket and/or SecureConnection objects are closed.");
    }

}

std::int32_t NetworkStream::Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {
    return NetworkStream::Receive(data, offset, size, SocketFlags::NONE);
}

std::int32_t NetworkStream::Receive(const std::span<std::uint8_t> data, const SocketFlags flags) const {
    return NetworkStream::Receive(data, 0, data.size(), flags);
}

std::int32_t NetworkStream::Receive(const std::span<std::uint8_t> data) const {
    return NetworkStream::Receive(data, 0, data.size(), SocketFlags::NONE);
}

void NetworkStream::Close() {

    try {
        if (this->m_ssl) this->m_ssl->Close();
        this->m_socket->Close();
    }
    catch (const InvalidObjectStateException&) {
        throw InvalidObjectStateException("The underlying Socket and/or SecureConnection objects are closed.");
    }

}