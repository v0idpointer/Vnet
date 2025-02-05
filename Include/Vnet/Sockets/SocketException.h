/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_SOCKETEXCEPTION_H_
#define _VNETCORE_SOCKETS_SOCKETEXCEPTION_H_

#include <Vnet/Exports.h>

#include <string>
#include <cstdint>
#include <exception>
#include <stdexcept>

namespace Vnet::Sockets {

    /**
     * An exception that is thrown when a socket or a network error occurs.
     */
    class VNETCOREAPI SocketException : public std::runtime_error {

    private:
        std::int32_t m_errorCode;

    public:

        /**
         * Constructs a new SocketException object.
         * 
         * @param errorCode An operating system-specific error code. 
         */
        SocketException(const std::int32_t errorCode);

        /**
         * Constructs a new SocketException object.
         * 
         * @param errorCode An operating system-specific error code. 
         * @param message An error message.
         */
        SocketException(const std::int32_t errorCode, const std::string& message);

        /**
         * Constructs a new SocketException object by copying an existing one.
         * 
         * @param other A SocketException object to copy.
         */
        SocketException(const SocketException& other) noexcept;

        SocketException(SocketException&& other) noexcept;
        virtual ~SocketException(void);

        SocketException& operator= (const SocketException& other) noexcept;
        SocketException& operator= (SocketException&& other) noexcept;

        /**
         * Returns the operating system-specific error code.
         * 
         * @returns An integer.
         */
        std::int32_t GetErrorCode(void) const;

    private:
        static std::string GetMessageFromErrorCode(const std::int32_t errorCode);

    };

}

#endif // _VNETCORE_SOCKETS_SOCKETEXCEPTION_H_