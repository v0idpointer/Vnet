/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_IPSOCKETADDRESS_H_
#define _VNETCORE_SOCKETS_IPSOCKETADDRESS_H_

#include <Vnet/Exports.h>
#include <Vnet/IpAddress.h>
#include <Vnet/Sockets/ISocketAddress.h>

namespace Vnet::Sockets {

    class VNETCOREAPI IpSocketAddress : public ISocketAddress {

    private:
        IpAddress m_ipAddr;
        Port m_port;

    public:
        IpSocketAddress(void);
        IpSocketAddress(const IpAddress& ipAddr, const Port port);
        IpSocketAddress(const IpSocketAddress& sockaddr);
        IpSocketAddress(IpSocketAddress&& sockaddr) noexcept;
        virtual ~IpSocketAddress(void);

        IpSocketAddress& operator= (const IpSocketAddress& sockaddr);
        IpSocketAddress& operator= (IpSocketAddress&& sockaddr) noexcept;
        bool operator== (const IpSocketAddress& sockaddr) const;

        AddressFamily GetAddressFamily(void) const override;
        IpAddress GetIpAddress(void) const;
        Port GetPort(void) const;

        void SetIpAddress(const IpAddress& ipAddr);
        void SetPort(const Port port);

    };

}

#endif // _VNETCORE_SOCKETS_IPSOCKETADDRESS_H_