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

        /**
         * Constructs a new SystemNotSupportedException object.
         */
        SystemNotSupportedException(void);

        /**
         * Constructs a new SystemNotSupportedException object.
         * 
         * @param message An error message.
         */
        SystemNotSupportedException(const std::string& message);

        /**
         * Constructs a new SystemNotSupportedException object by copying an existing one.
         * 
         * @param other A SystemNotSupportedException object to copy.
         */
        SystemNotSupportedException(const SystemNotSupportedException& other) noexcept;

        SystemNotSupportedException(SystemNotSupportedException&& other) noexcept;
        virtual ~SystemNotSupportedException(void);

        SystemNotSupportedException& operator= (const SystemNotSupportedException& other) noexcept;
        SystemNotSupportedException& operator= (SystemNotSupportedException&& other) noexcept;

    };

}

#endif // _VNETCORE_SYSTEMNOTSUPPORTEDEXCEPTION_H_