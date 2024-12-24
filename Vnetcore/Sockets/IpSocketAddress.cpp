/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/Sockets/Socket.h>
#include <Vnet/Sockets/IpSocketAddress.h>

using namespace Vnet;
using namespace Vnet::Sockets;

IpSocketAddress::IpSocketAddress() : IpSocketAddress(IpAddress::ANY, 0) { }

IpSocketAddress::IpSocketAddress(const IpAddress& ipAddr, const Port port) {
    this->m_ipAddr = ipAddr;
    this->m_port = port;
}

IpSocketAddress::IpSocketAddress(const IpSocketAddress& sockaddr) {
    this->operator= (sockaddr);
}

IpSocketAddress::IpSocketAddress(IpSocketAddress&& sockaddr) noexcept {
    this->operator= (std::move(sockaddr));
}

IpSocketAddress::~IpSocketAddress() { }

IpSocketAddress& IpSocketAddress::operator= (const IpSocketAddress& sockaddr) {

    if (this != &sockaddr) {
        this->m_ipAddr = sockaddr.m_ipAddr;
        this->m_port = sockaddr.m_port;
    }

    return static_cast<IpSocketAddress&>(*this);
}

IpSocketAddress& IpSocketAddress::operator= (IpSocketAddress&& sockaddr) noexcept {

    if (this != &sockaddr) {
        this->m_ipAddr = std::move(sockaddr.m_ipAddr);
        this->m_port = sockaddr.m_port;
    }

    return static_cast<IpSocketAddress&>(*this);
}

bool IpSocketAddress::operator== (const IpSocketAddress& sockaddr) const {
    return ((this->m_ipAddr == sockaddr.m_ipAddr) && (this->m_port == sockaddr.m_port));
}

AddressFamily IpSocketAddress::GetAddressFamily() const {
    return this->m_ipAddr.GetAddressFamily();
}

IpAddress IpSocketAddress::GetIpAddress() const {
    return this->m_ipAddr;
}

Port IpSocketAddress::GetPort() const {
    return this->m_port;
}

void IpSocketAddress::SetIpAddress(const IpAddress& ipAddr) {
    this->m_ipAddr = ipAddr;
}

void IpSocketAddress::SetPort(const Port port) {
    this->m_port = port;
}