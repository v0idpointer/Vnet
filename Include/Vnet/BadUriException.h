/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETHTTP_BADURIEXCEPTION_H_
#define _VNETHTTP_BADURIEXCEPTION_H_

#include <Vnet/Exports.h>

#include <string>
#include <exception>
#include <stdexcept>

namespace Vnet {

    class VNETHTTPAPI BadUriException : public std::runtime_error {

    public:
        BadUriException(const std::string& message);
        BadUriException(const BadUriException& other) noexcept;
        BadUriException(BadUriException&& other) noexcept;
        virtual ~BadUriException(void);

        BadUriException& operator= (const BadUriException& other) noexcept;
        BadUriException& operator= (BadUriException&& other) noexcept;

    };

}

#endif // _VNETHTTP_BADURIEXCEPTION_H_