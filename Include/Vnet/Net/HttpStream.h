/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETWEB_NET_HTTPSTREAM_H_
#define _VNETWEB_NET_HTTPSTREAM_H_

#include <Vnet/Http/HttpRequest.h>
#include <Vnet/Http/HttpResponse.h>
#include <Vnet/Net/NetworkStream.h>
#include <Vnet/Net/TransferEncoding.h>

namespace Vnet::Net {

    /**
     * 
     */
    class VNETWEBAPI HttpStream : public NetworkStream {

    public:
        HttpStream(const NetworkStream& stream);
        HttpStream(std::shared_ptr<Vnet::Sockets::Socket> socket, std::shared_ptr<Vnet::Security::SecureConnection> ssl);
        HttpStream(const HttpStream& stream);
        HttpStream(HttpStream&& stream) noexcept;
        virtual ~HttpStream(void);

        HttpStream& operator= (const HttpStream& stream);
        HttpStream& operator= (HttpStream&& stream) noexcept;

        // ... 

    };

}

#endif // _VNETWEB_NET_HTTPSTREAM_H_