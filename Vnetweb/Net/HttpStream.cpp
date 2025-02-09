/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Net/HttpStream.h>

#include <cstring>
#include <utility>
#include <list>
#include <chrono>
#include <thread>

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

std::vector<std::uint8_t> HttpStream::ReadData() const {

    std::vector<std::pair<std::vector<std::uint8_t>, std::size_t>> buffers = { };

    std::int32_t available = 0;
    while ((available = this->GetAvailableBytes()) > 0) {

        std::vector<std::uint8_t> buffer(available);
        std::int32_t read = this->Receive(buffer);

        buffers.emplace_back(std::move(buffer), read);

    }

    std::size_t totalSize = 0;
    for (const auto& [_, size] : buffers)
        totalSize += size;

    std::size_t pos = 0;
    std::vector<std::uint8_t> finalBuffer(totalSize);
    for (const auto& [buffer, size] : buffers) {
        memcpy(finalBuffer.data() + pos, buffer.data(), size);
        pos += size;
    }

    return finalBuffer;
}