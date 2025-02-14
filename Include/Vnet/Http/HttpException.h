/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPEXCEPTION_H_
#define _VNETHTTP_HTTP_HTTPEXCEPTION_H_

#include <Vnet/Http/HttpStatusCode.h>

#include <exception>
#include <stdexcept>

namespace Vnet::Http {

    /**
     * An exception that is thrown when an HTTP-related error occurs.
     */
    class VNETHTTPAPI HttpException : public std::runtime_error {

    private:
        std::optional<HttpStatusCode> m_statusCode;

    public:

        /**
         * Constructs a new HttpException object.
         * 
         * @param message An error message.
         */
        HttpException(const std::string& message);

        /**
         * Constructs a new HttpException object.
         * 
         * @param message An error message.
         * @param statusCode An HTTP response status code associated with the HTTP error.
         */
        HttpException(const std::string& message, const std::optional<HttpStatusCode>& statusCode);

        /**
         * Constructs a new HttpException object by copying an existing one.
         * 
         * @param other An HttpException object to copy.
         */
        HttpException(const HttpException& other) noexcept;

        HttpException(HttpException&& other) noexcept;
        virtual ~HttpException(void);

        /**
         * Assigns the value from an existing HttpException object to this object.
         * 
         * @param other An HttpException object to copy.
         */
        HttpException& operator= (const HttpException& other) noexcept;

        HttpException& operator= (HttpException&& other) noexcept;

        /**
         * Returns the HTTP response status code associated with the HTTP error.
         * 
         * @returns An optional HTTP response status code.
         */
        const std::optional<HttpStatusCode>& GetStatusCode(void) const;

    };

}

#endif // _VNETHTTP_HTTP_HTTPEXCEPTION_H_