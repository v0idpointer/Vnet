/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_SECURITY_SECURITYEXCEPTION_H_
#define _VNETSEC_SECURITY_SECURITYEXCEPTION_H_

#include <Vnet/Exports.h>

#include <string>
#include <cstdint>
#include <exception>
#include <stdexcept>

namespace Vnet::Security {

    typedef unsigned long ErrorCode_t;

    /**
     * An exception that is thrown when a cryptographic or a security error occurs.
     */
    class VNETSECURITYAPI SecurityException : public std::runtime_error {

    private:
        ErrorCode_t m_errorCode;

    public:

        /**
         * Constructs a new SecurityException object.
         * 
         * @param errorCode An error code.
         */
        SecurityException(const ErrorCode_t errorCode);

        /**
         * Constructs a new SecurityException object.
         * 
         * @param errorCode An error code.
         * @param message An error message.
         */
        SecurityException(const ErrorCode_t errorCode, const std::string& message);

        /**
         * Constructs a new SecurityException object by copying an existing one.
         * 
         * @param other A SecurityException object to copy.
         */
        SecurityException(const SecurityException& other) noexcept;

        SecurityException(SecurityException&& other) noexcept;
        virtual ~SecurityException(void);

        SecurityException& operator= (const SecurityException& other) noexcept;
        SecurityException& operator= (SecurityException&& other) noexcept;

        /**
         * Returns the error code.
         * 
         * @returns An ErrorCode_t.
         */
        ErrorCode_t GetErrorCode(void) const;

    private:
        static std::string GetMessageFromErrorCode(const ErrorCode_t errorCode);

    };

}

#endif // _VNETSEC_SECURITY_SECURITYEXCEPTION_H_