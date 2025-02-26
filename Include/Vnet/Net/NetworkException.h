/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETWEB_NET_NETWORKEXCEPTION_H_
#define _VNETWEB_NET_NETWORKEXCEPTION_H_

#include <Vnet/Exports.h>

#include <string>
#include <exception>
#include <stdexcept>

namespace Vnet::Net {

    class VNETWEBAPI NetworkException : public std::runtime_error {

    public:
        NetworkException(const std::string& message);
        NetworkException(const NetworkException& other) noexcept;
        NetworkException(NetworkException&& other) noexcept;
        virtual ~NetworkException(void);

        NetworkException& operator= (const NetworkException& other) noexcept;
        NetworkException& operator= (NetworkException&& other) noexcept;

    };

}

#endif // _VNETWEB_NET_NETWORKEXCEPTION_H_