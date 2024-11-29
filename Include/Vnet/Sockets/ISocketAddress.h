/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_ISOCKETADDRESS_H_
#define _VNETCORE_SOCKETS_ISOCKETADDRESS_H_

#include <Vnet/Exports.h>
#include <Vnet/Sockets/AddressFamily.h>

namespace Vnet::Sockets {

    class VNETCOREAPI ISocketAddress {
    public:
        virtual ~ISocketAddress(void) { };
        virtual AddressFamily GetAddressFamily(void) const = 0;
    };

}

#endif // _VNETCORE_SOCKETS_ISOCKETADDRESS_H_