/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETCORE_INVALIDOBJECTSTATEEXCEPTION_H_
#define _VNETCORE_INVALIDOBJECTSTATEEXCEPTION_H_

#include <Vnet/Exports.h>

#include <string>
#include <exception>
#include <stdexcept>

namespace Vnet {

    class VNETCOREAPI InvalidObjectStateException : public std::runtime_error {

    public:
        InvalidObjectStateException(void);
        InvalidObjectStateException(const std::string& message);
        InvalidObjectStateException(const InvalidObjectStateException& other) noexcept;
        InvalidObjectStateException(InvalidObjectStateException&& other) noexcept;
        virtual ~InvalidObjectStateException(void);

        InvalidObjectStateException& operator= (const InvalidObjectStateException& other) noexcept;
        InvalidObjectStateException& operator= (InvalidObjectStateException&& other) noexcept;

    };

}

#endif // _VNETCORE_INVALIDOBJECTSTATEEXCEPTION_H_