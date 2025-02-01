/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
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

    class VNETSECURITYAPI SecurityException : public std::runtime_error {

    private:
        ErrorCode_t m_errorCode;

    public:
        SecurityException(const ErrorCode_t errorCode);
        SecurityException(const ErrorCode_t errorCode, const std::string& message);
        SecurityException(const SecurityException& other) noexcept;
        SecurityException(SecurityException&& other) noexcept;
        virtual ~SecurityException(void);

        SecurityException& operator= (const SecurityException& other) noexcept;
        SecurityException& operator= (SecurityException&& other) noexcept;

        ErrorCode_t GetErrorCode(void) const;

    private:
        static std::string GetMessageFromErrorCode(const ErrorCode_t errorCode);

    };

}

#endif // _VNETSEC_SECURITY_SECURITYEXCEPTION_H_