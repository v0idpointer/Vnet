/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Net/HttpStream.h>
#include <Vnet/Security/SecurityException.h>

#include <cstring>

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

std::list<std::pair<std::vector<std::uint8_t>, std::size_t>> HttpStream::ReadData() const {
    
    std::list<std::pair<std::vector<std::uint8_t>, std::size_t>> buffers = { };

    std::int32_t available = 0;
    std::int32_t lastBufferSize = -1;
    while (true) {

        available = this->GetAvailableBytes();
        if (available == 0) {

            if (!this->GetSocket()->Poll(PollEvent::READ, 100)) {
                if (available == lastBufferSize) break;
                lastBufferSize = available;
            }

            continue;
        }

        std::int32_t read = 0;
        std::vector<std::uint8_t> buffer(available);

        try { read = this->Receive(buffer); }
        catch (const SecurityException& ex) {       // SecureConnection::Receive throws a SecurityException (error code: 0)
            if (ex.GetErrorCode() == 0) continue;   // if the number of read bytes is zero. why? i don't fucking remember anymore.
            else throw ex;
        }

        buffers.emplace_back(std::move(buffer), read);
        lastBufferSize = read;

    }

    return buffers;
}

std::vector<std::uint8_t> HttpStream::ConcatBuffers(const std::list<std::pair<std::vector<std::uint8_t>, std::size_t>>& buffers) {

    std::size_t totalSize = 0;
    for (const auto& [_, size] : buffers)
        totalSize += size;

    std::size_t pos = 0;
    std::vector<std::uint8_t> finalBuffer(totalSize);
    for (const auto& [buffer, size] : buffers) {
        std::memcpy((finalBuffer.data() + pos), buffer.data(), size);
        pos += size;
    }

    return finalBuffer;
}

std::list<std::pair<std::vector<std::uint8_t>, std::size_t>> HttpStream::ParseChunkedTransferEncoding(const std::span<const std::uint8_t> data) {
    
    std::list<std::pair<std::vector<std::uint8_t>, std::size_t>> chunks = { };

    std::string_view text = { reinterpret_cast<const char*>(data.data()), data.size() };
    while (!text.empty()) {

        const std::size_t pos = text.find("\r\n");
        if (pos == std::string_view::npos)
            throw std::out_of_range("Bad chunk.");

        std::size_t chunkSize = 0;
        try {
            const std::string_view size = text.substr(0, pos);
            chunkSize = static_cast<std::size_t>(std::stoull(std::string(size), nullptr, 16));
        }
        catch (const std::invalid_argument&) {
            throw std::invalid_argument("Bad chunk size.");
        }
        catch (const std::out_of_range&) {
            throw std::out_of_range("Chunk too large.");
        }

        text = text.substr(pos + 2);

        if (chunkSize == 0) break;
        
        const std::string_view contents = text.substr(0, chunkSize);
        std::vector<std::uint8_t> buffer(chunkSize);
        std::memcpy(buffer.data(), contents.data(), chunkSize);
        chunks.emplace_back(std::move(buffer), chunkSize);
        
        text = text.substr(chunkSize + 2);

    }

    return chunks;
}