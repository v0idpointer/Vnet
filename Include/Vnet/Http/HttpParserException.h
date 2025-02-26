/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_HTTPPARSEREXCEPTION_H_
#define _VNETHTTP_HTTP_HTTPPARSEREXCEPTION_H_

#include <Vnet/Http/HttpException.h>

namespace Vnet::Http {

    class VNETHTTPAPI HttpParserException : public HttpException {

    public:
        HttpParserException(const std::string& message);
        HttpParserException(const std::string& message, const std::optional<HttpStatusCode>& statusCode);
        HttpParserException(const HttpParserException& other) noexcept;
        HttpParserException(HttpParserException&& other) noexcept;
        virtual ~HttpParserException(void);

        HttpParserException& operator= (const HttpParserException& other) noexcept;
        HttpParserException& operator= (HttpParserException&& other) noexcept;

    };

}

#endif // _VNETHTTP_HTTP_HTTPPARSEREXCEPTION_H_