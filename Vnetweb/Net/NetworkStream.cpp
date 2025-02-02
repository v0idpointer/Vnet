/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Net/NetworkStream.h>

#include <exception>
#include <stdexcept>

using namespace Vnet::Net;
using namespace Vnet::Security;
using namespace Vnet::Sockets;

NetworkStream::NetworkStream(std::shared_ptr<Socket> socket, std::shared_ptr<SecureConnection> ssl)
    : m_socket(std::move(socket)), m_ssl(std::move(ssl)) { }

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

    if (this->m_ssl) return this->m_ssl->GetAvailableBytes();
    else if (this->m_socket) return this->m_socket->GetAvailableBytes();
    else throw std::runtime_error("Bad network stream.");

}

std::int32_t NetworkStream::Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const {

    if (flags != SocketFlags::NONE)
        throw std::invalid_argument("'flags': This value must be SocketFlags::NONE.");

    if (this->m_ssl) return this->m_ssl->Send(data, offset, size, flags);
    else if (this->m_socket) return this->m_socket->Send(data, offset, size, flags);
    else throw std::runtime_error("Bad network stream.");

}

std::int32_t NetworkStream::Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {
    return this->Send(data, offset, size, SocketFlags::NONE);
}

std::int32_t NetworkStream::Send(const std::span<const std::uint8_t> data, const SocketFlags flags) const {
    return this->Send(data, 0, data.size(), flags);
}

std::int32_t NetworkStream::Send(const std::span<const std::uint8_t> data) const {
    return this->Send(data, 0, data.size(), SocketFlags::NONE);
}

std::int32_t NetworkStream::Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const {

    if ((flags != SocketFlags::NONE) && (flags != SocketFlags::PEEK))
        throw std::invalid_argument("'flags': This value must be SocketFlags::NONE or SocketFlags::PEEK.");

    if (this->m_ssl) return this->m_ssl->Receive(data, offset, size, flags);
    else if (this->m_socket) return this->m_socket->Receive(data, offset, size, flags);
    else throw std::runtime_error("Bad network stream.");

}

std::int32_t NetworkStream::Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {
    return this->Receive(data, offset, size, SocketFlags::NONE);
}

std::int32_t NetworkStream::Receive(const std::span<std::uint8_t> data, const SocketFlags flags) const {
    return this->Receive(data, 0, data.size(), flags);
}

std::int32_t NetworkStream::Receive(const std::span<std::uint8_t> data) const {
    return this->Receive(data, 0, data.size(), SocketFlags::NONE);
}

void NetworkStream::Close() {

    if ((this->m_socket == nullptr) && (this->m_ssl == nullptr))
        throw std::runtime_error("Bad network stream.");

    if (this->m_ssl) this->m_ssl->Close();
    if (this->m_socket) this->m_socket->Close();

}