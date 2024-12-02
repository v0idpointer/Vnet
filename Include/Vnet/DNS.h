/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_DNS_H_
#define _VNETCORE_DNS_H_

#include <Vnet/Exports.h>
#include <Vnet/DnsLookupResult.h>

namespace Vnet {

    class VNETCOREAPI DNS final {

    public:
        DNS(void) = delete;

        static DnsLookupResult Resolve(const std::string_view hostname);
        static DnsLookupResult Resolve(const IpAddress& ipAddress);

    };

}

#endif // _VNETCORE_DNS_H_