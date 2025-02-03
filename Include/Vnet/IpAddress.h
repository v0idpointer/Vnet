/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETCORE_IPADDRESS_H_
#define _VNETCORE_IPADDRESS_H_

#include <Vnet/Exports.h>
#include <Vnet/Sockets/AddressFamily.h>

#include <string>
#include <string_view>
#include <cstdint>
#include <vector>
#include <optional>
#include <span>

namespace Vnet {

    /**
     * Represents a network port number.
     */
    typedef std::uint16_t Port;

    /** Port number used for HTTP */
    constexpr Port HTTP_PORT = 80;

    /** Port number used for HTTPS */
    constexpr Port HTTPS_PORT = 443;

    /**
     * Represents an IPv4 or an IPv6 address.
     */
    class VNETCOREAPI IpAddress {

    public:

        /**
         * 0.0.0.0
         */
        static const IpAddress ANY;

        /**
         * 127.0.0.1
         */
        static const IpAddress LOCALHOST;

        /**
         * 255.255.255.255
         */
        static const IpAddress BROADCAST;

        /**
         * ::
         */
        static const IpAddress ANY_V6;

        /**
         * ::1
         */
        static const IpAddress LOCALHOST_V6;

    private:
        std::vector<std::uint8_t> m_bytes;

    public:
        IpAddress(void);
        IpAddress(const std::uint8_t aa, const std::uint8_t bb, const std::uint8_t cc, const std::uint8_t dd);
        IpAddress(const std::span<const std::uint8_t> bytes);
        IpAddress(const IpAddress& address);
        IpAddress(IpAddress&& address) noexcept;
        virtual ~IpAddress(void);

        IpAddress& operator= (const IpAddress& address);
        IpAddress& operator= (IpAddress&& address) noexcept;
        bool operator== (const IpAddress& address) const;

        /**
         * Returns true if the IP address is an IPv6 address.
         */
        bool IsVersion6(void) const;

        /**
         * Returns true if the IP address is a public IP address.
         */
        bool IsPublicAddress(void) const;

        /**
         * Returns true if the IP address is a private IP address.
         */
        bool IsPrivateAddress(void) const;

        /**
         * Returns the address family of the IP address.
         * 
         * @returns AddressFamily::IPV4 or AddressFamily::IPV6
         */
        Vnet::Sockets::AddressFamily GetAddressFamily(void) const;

        /**
         * Returns the string representation of the IP address.
         */
        std::string ToString(void) const;

    private:
        static std::optional<IpAddress> ParseVersion4(const std::string_view address, const bool exceptions);
        static std::optional<IpAddress> ParseVersion6(const std::string_view address, const bool exceptions);

    public:

        /**
         * Parses a string representation of an IP address.
         * 
         * @param address A string containing an IPv4 or an IPv6 address.
         * @returns An IpAddress object.
         * @exception std::invalid_argument - The 'address' parameter contains an invalid IP address.
         */
        static IpAddress Parse(const std::string_view address);

        /**
         * Tries to parse a string representation of an IP address.
         * 
         * @param address A string containing an IPv4 or an IPv6 address.
         * @returns If successful, an IpAddress object is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<IpAddress> TryParse(const std::string_view address);

    };

}

#endif // _VNETCORE_IPADDRESS_H_