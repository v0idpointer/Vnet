/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPMETHOD_H_
#define _VNETHTTP_HTTP_HTTPMETHOD_H_

#include <Vnet/Exports.h>

#include <string>
#include <string_view>

namespace Vnet::Http {

    /**
     * Represents an HTTP request method.
     */
    class VNETHTTPAPI HttpMethod {

    public:
        static const HttpMethod GET;
        static const HttpMethod HEAD;
        static const HttpMethod POST;
        static const HttpMethod PUT;
        static const HttpMethod DELETE;
        static const HttpMethod CONNECT;
        static const HttpMethod OPTIONS;
        static const HttpMethod TRACE;
        static const HttpMethod PATCH;

    private:
        std::string m_name;

    public:
        HttpMethod(const std::string_view name);
        HttpMethod(const HttpMethod& method);
        HttpMethod(HttpMethod&& method) noexcept;
        virtual ~HttpMethod(void);

        HttpMethod& operator= (const HttpMethod& method);
        HttpMethod& operator= (HttpMethod&& method) noexcept;
        bool operator== (const HttpMethod& method) const;

        /**
         * Returns the name of the request method.
         * 
         * @returns A string.
         */
        const std::string& GetName(void) const;

        /**
         * Returns the string representation of the HttpMethod object.
         * 
         * @returns A string. 
         */
        std::string ToString(void) const;

    };

}

#endif // _VNETHTTP_HTTP_HTTPMETHOD_H_