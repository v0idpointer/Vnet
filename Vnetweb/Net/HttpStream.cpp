/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Net/HttpStream.h>

using namespace Vnet::Sockets;
using namespace Vnet::Security;
using namespace Vnet::Http;
using namespace Vnet::Net;

HttpStream::HttpStream(const NetworkStream& stream)
    : HttpStream(stream.GetSocket(), stream.GetSecureConnection()) { }

HttpStream::HttpStream(std::shared_ptr<Socket> socket, std::shared_ptr<SecureConnection> ssl)
    : NetworkStream(socket, ssl) { }

HttpStream::HttpStream(const HttpStream& stream) : NetworkStream(stream) { }

HttpStream::HttpStream(HttpStream&& stream) noexcept : NetworkStream(std::move(stream)) { }

HttpStream::~HttpStream() { }

HttpStream& HttpStream::operator= (const HttpStream& stream) {
    if (this != &stream) NetworkStream::operator= (stream);
    return static_cast<HttpStream&>(*this);
}

HttpStream& HttpStream::operator= (HttpStream&& stream) noexcept {
    if (this != &stream) NetworkStream::operator= (std::move(stream));
    return static_cast<HttpStream&>(*this);
}