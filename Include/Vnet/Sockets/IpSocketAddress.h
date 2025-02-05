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

        /**
         * Constructs a new IpSocketAddress object.
         */
        IpSocketAddress(void);

        /**
         * Constructs a new IpSocketAddress object.
         * 
         * @param ipAddr An IP address.
         * @param port A port number.
         */
        IpSocketAddress(const IpAddress& ipAddr, const Port port);

        /**
         * Constructs a new IpSocketAddress by copying an existing one.
         * 
         * @param sockaddr An IpSocketAddress object to copy.
         */
        IpSocketAddress(const IpSocketAddress& sockaddr);

        IpSocketAddress(IpSocketAddress&& sockaddr) noexcept;
        virtual ~IpSocketAddress(void);

        /**
         * Assigns the value from an existing IpSocketAddress object to this object.
         * 
         * @param sockaddr An IpSocketAddress object to copy.
         */
        IpSocketAddress& operator= (const IpSocketAddress& sockaddr);
        
        IpSocketAddress& operator= (IpSocketAddress&& sockaddr) noexcept;

        /**
         * Compares this IpSocketAddress object with another for equality.
         * 
         * @param sockaddr An IpSocketAddress to compare with.
         * @returns true if the IpSocketAddress objects are equal; otherwise, false.
         */
        bool operator== (const IpSocketAddress& sockaddr) const;

        /**
         * Returns the IP address' address family.
         * 
         * @returns AddressFamily::IPV4 or AddressFamily::IPV6
         */
        AddressFamily GetAddressFamily(void) const override;

        /**
         * Returns the IP address.
         * 
         * @returns An IpAddress.
         */
        IpAddress GetIpAddress(void) const;

        /**
         * Returns the port number.
         * 
         * @returns A Port.
         */
        Port GetPort(void) const;

        /**
         * Sets the IP address.
         * 
         * @param ipAddr An IP address.
         */
        void SetIpAddress(const IpAddress& ipAddr);

        /**
         * Sets the port number.
         * 
         * @param port A port number.
         */
        void SetPort(const Port port);

    };

}

#endif // _VNETCORE_SOCKETS_IPSOCKETADDRESS_H_