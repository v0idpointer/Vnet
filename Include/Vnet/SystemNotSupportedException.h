/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETCORE_SYSTEMNOTSUPPORTEDEXCEPTION_H_
#define _VNETCORE_SYSTEMNOTSUPPORTEDEXCEPTION_H_

#include <Vnet/Exports.h>

#include <string>
#include <exception>
#include <stdexcept>

namespace Vnet {

    /**
     * An exception that is thrown when a feature is not supported on the current environment.
     */
    class VNETCOREAPI SystemNotSupportedException : public std::runtime_error {

    public:
        SystemNotSupportedException(void);
        SystemNotSupportedException(const std::string& message);
        SystemNotSupportedException(const SystemNotSupportedException& other) noexcept;
        SystemNotSupportedException(SystemNotSupportedException&& other) noexcept;
        virtual ~SystemNotSupportedException(void);

        SystemNotSupportedException& operator= (const SystemNotSupportedException& other) noexcept;
        SystemNotSupportedException& operator= (SystemNotSupportedException&& other) noexcept;

    };

}

#endif // _VNETCORE_SYSTEMNOTSUPPORTEDEXCEPTION_H_