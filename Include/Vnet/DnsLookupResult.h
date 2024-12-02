/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_DNSLOOKUPRESULT_H_
#define _VNETCORE_DNSLOOKUPRESULT_H_

#include <Vnet/Exports.h>
#include <Vnet/IpAddress.h>

#include <string>
#include <string_view>
#include <vector>

namespace Vnet {

    class VNETCOREAPI DnsLookupResult {

    private:
        std::string m_canonicalName;
        std::vector<IpAddress> m_addresses;

    public:
        DnsLookupResult(void);
        DnsLookupResult(const std::string_view canonicalName, const IpAddress& address);
        DnsLookupResult(const std::string_view canonicalName, const std::vector<IpAddress>& addresses);
        DnsLookupResult(const std::string_view canonicalName, std::vector<IpAddress>&& addresses) noexcept;
        DnsLookupResult(const DnsLookupResult& result);
        DnsLookupResult(DnsLookupResult&& result) noexcept;
        virtual ~DnsLookupResult(void);

        DnsLookupResult& operator= (const DnsLookupResult& result);
        DnsLookupResult& operator= (DnsLookupResult&& result) noexcept;
        bool operator== (const DnsLookupResult& result) const;

        const std::string& GetCanonicalName(void) const;
        const std::vector<IpAddress>& GetAddresses(void) const;
        std::vector<IpAddress>& GetAddresses(void);

        void SetCanonicalName(const std::string_view canonicalName);
        void SetAddresses(const std::vector<IpAddress>& addresses);
        void SetAddresses(std::vector<IpAddress>&& addresses) noexcept;

    };

}

#endif // _VNETCORE_DNSLOOKUPRESULT_H_