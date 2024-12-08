/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
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

    typedef std::uint16_t Port;

    class VNETCOREAPI IpAddress {

    public:
        static const IpAddress ANY;
        static const IpAddress LOCALHOST;
        static const IpAddress BROADCAST;
        static const IpAddress ANY_V6;
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

        bool IsVersion6(void) const;
        bool IsPublicAddress(void) const;
        bool IsPrivateAddress(void) const;
        Vnet::Sockets::AddressFamily GetAddressFamily(void) const;

        std::string ToString(void) const;

    private:
        static std::optional<IpAddress> ParseVersion4(const std::string_view address, const bool exceptions);
        static std::optional<IpAddress> ParseVersion6(const std::string_view address, const bool exceptions);

    public:
        static IpAddress Parse(const std::string_view address);
        static std::optional<IpAddress> TryParse(const std::string_view address);

    };

}

#endif // _VNETCORE_IPADDRESS_H_