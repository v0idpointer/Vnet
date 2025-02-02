/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_IPSOCKETADDRESS_H_
#define _VNETCORE_SOCKETS_IPSOCKETADDRESS_H_

#include <Vnet/Exports.h>
#include <Vnet/IpAddress.h>
#include <Vnet/Sockets/ISocketAddress.h>

namespace Vnet::Sockets {

    /**
     * Represents an ISocketAddress implementation for IPv4 and IPv6 addresses.
     */
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

        /**
         * @returns AddressFamily::IPV4 or AddressFamily::IPV6
         */
        AddressFamily GetAddressFamily(void) const override;

        /**
         * Returns the IP address.
         */
        IpAddress GetIpAddress(void) const;

        /**
         * Returns the port number.
         */
        Port GetPort(void) const;

        /**
         * Sets the IP address.
         */
        void SetIpAddress(const IpAddress& ipAddr);

        /**
         * Sets the port number.
         */
        void SetPort(const Port port);

    };

}

#endif // _VNETCORE_SOCKETS_IPSOCKETADDRESS_H_