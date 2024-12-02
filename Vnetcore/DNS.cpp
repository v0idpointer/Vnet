/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/DNS.h>
#include <Vnet/Sockets/SocketException.h>

#include "SocketsApi.h"
#include "Sockets/Native.h"

#include <optional>

using namespace Vnet;
using namespace Vnet::Sockets;

DnsLookupResult DNS::Resolve(const std::string_view hostname) {

    std::optional<std::string> canonicalName;
    std::vector<IpAddress> addresses = { };

    struct addrinfo* result = nullptr, *ptr = nullptr, hints = { 0 };
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = (AI_CANONNAME | AI_ALL);

    std::int32_t res = getaddrinfo(
        hostname.data(),
        nullptr,
        &hints,
        &result
    );

    if ((res == -1) || (result == nullptr)) 
        throw SocketException(Native::GetLastErrorCode());

    for (ptr = result; ptr != nullptr; ptr = ptr->ai_next) {

        if ((ptr->ai_family != AF_INET) && (ptr->ai_family != AF_INET6)) continue;

        if (ptr->ai_canonname && !canonicalName)
            canonicalName = { ptr->ai_canonname };

        if (ptr->ai_family == AF_INET) {
            struct sockaddr_in* sockaddr = reinterpret_cast<struct sockaddr_in*>(ptr->ai_addr);
            addresses.push_back(Native::ToIpAddress4(sockaddr));
        }
        else {
            struct sockaddr_in6* sockaddr = reinterpret_cast<struct sockaddr_in6*>(ptr->ai_addr);
            addresses.push_back(Native::ToIpAddress6(sockaddr));
        }

    }

    freeaddrinfo(result);

    return { canonicalName.value_or(""), std::move(addresses) };
}

DnsLookupResult DNS::Resolve(const IpAddress& ipAddress) {
    return DNS::Resolve(ipAddress.ToString());
}