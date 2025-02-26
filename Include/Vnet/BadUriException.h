/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_BADURIEXCEPTION_H_
#define _VNETHTTP_BADURIEXCEPTION_H_

#include <Vnet/Exports.h>

#include <string>
#include <exception>
#include <stdexcept>

namespace Vnet {

    /**
     * An exception that is thrown when a Uniform Resource Identifier (URI) is invalid.
     */
    class VNETHTTPAPI BadUriException : public std::runtime_error {

    public:

        /**
         * Constructs a new BadUriException object.
         */
        BadUriException(void);

        /**
         * Constructs a new BadUriException object.
         * 
         * @param message An error message.
         */
        BadUriException(const std::string& message);

        /**
         * Constructs a new BadUriException object by copying an existing one.
         * 
         * @param other A BadUriException object to copy.
         */
        BadUriException(const BadUriException& other) noexcept;
        
        BadUriException(BadUriException&& other) noexcept;
        virtual ~BadUriException(void);

        BadUriException& operator= (const BadUriException& other) noexcept;
        BadUriException& operator= (BadUriException&& other) noexcept;

    };

}

#endif // _VNETHTTP_BADURIEXCEPTION_H_