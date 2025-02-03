/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETCORE_DNS_H_
#define _VNETCORE_DNS_H_

#include <Vnet/Exports.h>
#include <Vnet/DnsLookupResult.h>

namespace Vnet {

    /**
     * Contains functions for domain name resolutions.
     */
    class VNETCOREAPI DNS final {

    public:
        DNS(void) = delete;

        /**
         * Resolves a hostname.
         * 
         * @param hostname A hostname.
         * @returns A canonical name and a list of IP addresses, stored in a DnsLookupResult.
         * @exception SocketException - Domain name resolution failed.
         */
        static DnsLookupResult Resolve(const std::string_view hostname);

        /**
         * Resolves an IP address.
         * 
         * @param ipAddress An IP address.
         * @returns A canonical name and a list of IP addresses, stored in a DnsLookupResult.
         * @exception SocketException - Domain name resolution failed.
         */
        static DnsLookupResult Resolve(const IpAddress& ipAddress);

    };

}

#endif // _VNETCORE_DNS_H_