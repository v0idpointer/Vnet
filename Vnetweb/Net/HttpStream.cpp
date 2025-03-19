/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Net/HttpStream.h>
#include <Vnet/Net/NetworkException.h>
#include <Vnet/Security/SecurityException.h>
#include <Vnet/Http/HttpParserException.h>
#include <Vnet/InvalidObjectStateException.h>

#include <cstring>
#include <sstream>
#include <algorithm>
#include <type_traits>

using namespace Vnet::Sockets;
using namespace Vnet::Security;
using namespace Vnet::Http;
using namespace Vnet::Net;
using namespace Vnet;

HttpStream::HttpStream(const NetworkStream& stream)
    : HttpStream(stream.GetSocket(), stream.GetSecureConnection()) { }

HttpStream::HttpStream(std::shared_ptr<Socket> socket, std::shared_ptr<SecureConnection> ssl)
    : NetworkStream(std::move(socket), std::move(ssl)) {

    this->m_networkOptions = NetworkOptions::DEFAULT_OPTIONS;
    this->m_httpOptions = HttpParserOptions::DEFAULT_OPTIONS;
    this->m_transferEncoding = TransferEncoding::NONE;

}

HttpStream::HttpStream(const HttpStream& stream) : NetworkStream(stream) { }

HttpStream::HttpStream(HttpStream&& stream) noexcept : NetworkStream(std::move(stream)) { }

HttpStream::~HttpStream() { }

HttpStream& HttpStream::operator= (const HttpStream& stream) {
    
    if (this != &stream) {
        NetworkStream::operator= (stream);
        this->m_networkOptions = stream.m_networkOptions;
        this->m_httpOptions = stream.m_httpOptions;
        this->m_transferEncoding = stream.m_transferEncoding;
    }

    return static_cast<HttpStream&>(*this);
}

HttpStream& HttpStream::operator= (HttpStream&& stream) noexcept {
    
    if (this != &stream) {
        NetworkStream::operator= (std::move(stream));
        this->m_networkOptions = std::move(stream.m_networkOptions);
        this->m_httpOptions = std::move(stream.m_httpOptions);
        this->m_transferEncoding = stream.m_transferEncoding;
    }

    return static_cast<HttpStream&>(*this);
}

std::list<std::pair<std::vector<std::uint8_t>, std::size_t>> HttpStream::ReadData() const {
    
    std::list<std::pair<std::vector<std::uint8_t>, std::size_t>> buffers = { };

    std::int32_t available = 0;
    std::int32_t lastBufferSize = -1;
    std::size_t totalSize = 0;

    while (true) {

        available = this->GetAvailableBytes();
        if (available == 0) {

            if (!this->GetSocket()->Poll(PollEvent::READ, 100)) {
                if (available == lastBufferSize) break;
                lastBufferSize = available;
            }

            continue;
        }

        if (this->m_networkOptions.MaxReadLimit && ((totalSize + available) > *this->m_networkOptions.MaxReadLimit))
            throw NetworkException("Read limit exceeded.");

        std::int32_t read = 0;
        std::vector<std::uint8_t> buffer(available);

        try { read = NetworkStream::Receive(buffer); }
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

HttpHeaderCollection HttpStream::ParseHeaders(const std::span<const std::uint8_t> data, const Vnet::Http::HttpParserOptions& options) {

    std::string_view str = { reinterpret_cast<const char*>(data.data()), data.size() };
    const std::size_t start = (str.find("\r\n") + 2);
    const std::size_t end = str.find("\r\n\r\n");

    str = str.substr(start, (end - start));

    return HttpHeaderCollection::Parse(str, options);
}

template <typename T>
TransferEncoding HttpStream::ReceiveHttpMessage(T& msg) {

    // read the data from the network:
    const std::vector<std::uint8_t> data = HttpStream::ConcatBuffers(this->ReadData());
    if (data.empty())
        throw NetworkException("No data was read from the network.");

    // parse the http headers:
    HttpHeaderCollection headers;
    try { headers = HttpStream::ParseHeaders(data, this->m_httpOptions); }
    catch (const HttpParserException& ex) {

        using namespace std::string_literals;
        throw HttpParserException(
            ("The data read from the network does not contain a valid HTTP message: "s + ex.what()), 
            ex.GetStatusCode()
        );

    }
    catch (const std::exception&) {
        
        throw HttpParserException(
            "The data read from the network does not contain a valid HTTP message.", 
            HttpStatusCode::BAD_REQUEST
        );

    }

    // if transfer encoding is not used, parse the message regularly:
    if (!headers.Contains("Transfer-Encoding")) {
        msg = T::Parse(data, this->m_httpOptions);
        return TransferEncoding::NONE;
    }

    if (headers.Get("Transfer-Encoding").GetValue() != "chunked")
        throw HttpException("Invalid/unsupported transfer encoding.", std::nullopt);

    const std::uint8_t* delim = reinterpret_cast<const std::uint8_t*>("\r\n\r\n");
    const auto it = std::search(data.begin(), data.end(), delim, (delim + 4));
    if (it == data.end())
        throw HttpParserException(
            "The data read from the network does not contain a valid HTTP message.", 
            HttpStatusCode::BAD_REQUEST
        );

    const std::size_t pos = static_cast<std::size_t>(std::distance(data.begin(), it) + 4);
    const std::span<const std::uint8_t> message = { data.data(), pos };
    const std::span<const std::uint8_t> chunks = { (data.data() + pos), (data.size() - pos) };

    // parse the http message without the payload:
    try { msg = T::Parse(message, this->m_httpOptions); }
    catch (const HttpParserException& ex) {

        using namespace std::string_literals;
        throw HttpParserException(
            ("The data read from the network does not contain a valid HTTP message: "s + ex.what()), 
            ex.GetStatusCode()
        );

    }
    catch (const std::invalid_argument&) {
        
        throw HttpParserException(
            "The data read from the network does not contain a valid HTTP message.", 
            HttpStatusCode::BAD_REQUEST
        );

    }

    // parse the chunked data:
    std::vector<std::uint8_t> payload = { };
    try { payload = HttpStream::ConcatBuffers(HttpStream::ParseChunkedTransferEncoding(chunks)); }
    catch (const std::exception& ex) {
        
        std::string msg = ex.what();
        if (!msg.empty()) {
            char& ch = msg[0];
            if ((ch >= 'A') && (ch <= 'Z'))
                ch += ('a' - 'A');
        }

        msg = ("HTTP chunked encoding parser error: " + msg);
        throw HttpParserException(
            msg,
            HttpStatusCode::BAD_REQUEST
        );

    }

    if (this->m_httpOptions.MaxPayloadSize && (chunks.size() > *this->m_httpOptions.MaxPayloadSize))
        throw HttpParserException(
            "HTTP chunked encoding parser error: payload too large.",
            HttpStatusCode::CONTENT_TOO_LARGE
        );

    msg.GetHeaders().Remove("Transfer-Encoding");
    msg.SetPayload(std::move(payload));

    return TransferEncoding::CHUNKED;
}

std::int32_t HttpStream::SendData(const std::span<const std::uint8_t> data) const {

    std::size_t offset = 0;
    std::int32_t sent = 0;

    while (offset < data.size()) {

        std::size_t len = this->m_networkOptions.ChunkSize;
        if ((offset + len) > data.size())
            len = (data.size() - offset);

        const std::span<const std::uint8_t> chunk = data.subspan(offset, len);
        sent += NetworkStream::Send(chunk);

        offset += len;

    }

    return sent;
}

// "The specified HTTP message contains the Transfer-Encoding header that is incompatible with the transfer encoding used by the current HttpStream object."

template <typename T>
void HttpStream::SendHttpMessage(const T& msg) const {

    // check if the http message contains the transfer-encoding header,
    // and if yes, check that it matches the transfer encoding used by the http stream:
    std::optional<std::string> transferEncodingHdr;
    if (msg.GetHeaders().Contains("Transfer-Encoding"))
        transferEncodingHdr = msg.GetHeaders().Get("Transfer-Encoding").GetValue();

    const HttpException badTransferEncoding = { 
        "The specified HTTP message contains a Transfer-Encoding header that is incompatible with the transfer encoding used by the current HttpStream object." 
    };

    if ((this->m_transferEncoding == TransferEncoding::NONE) && transferEncodingHdr.has_value())
        throw badTransferEncoding;

    if ((this->m_transferEncoding == TransferEncoding::CHUNKED) && (transferEncodingHdr.has_value() && (transferEncodingHdr != "chunked")))
        throw badTransferEncoding;

    /* transfer encoding not used */

    if (this->m_transferEncoding == TransferEncoding::NONE) {
        this->SendData(msg.Serialize());
        return;
    }

    /* chunked transfer encoding used */

    // create a copy of the http message, without the payload:
    T duplicate;
    duplicate.SetHeaders(msg.GetHeaders());

    if constexpr (std::is_same<T, HttpRequest>::value) {
        duplicate.SetMethod(msg.GetMethod());
        duplicate.SetRequestUri(msg.GetRequestUri());
    }
    else if constexpr (std::is_same<T, HttpResponse>::value) {
        duplicate.SetStatusCode(msg.GetStatusCode());
    }

    // remove the content-length header and set the transfer-encoding header:
    duplicate.GetHeaders().Remove("Content-Length");
    duplicate.GetHeaders().Set("Transfer-Encoding", "chunked");

    // send the duplicate http message:
    this->SendData(duplicate.Serialize());

    // send the original payload in chunks:
    const std::span<const std::uint8_t> payload = msg.GetPayload();
    const std::size_t maxChunkSize = 0xFFFF;
    std::size_t offset = 0;

    while (offset < payload.size()) {

        std::size_t len = maxChunkSize;
        if ((offset + len) > payload.size())
            len = (payload.size() - offset);

        this->Send(payload.subspan(offset, len));
        offset += len;

    }

}

const NetworkOptions& HttpStream::GetNetworkOptions() const {
    return this->m_networkOptions;
}

NetworkOptions& HttpStream::GetNetworkOptions() {
    return this->m_networkOptions;
}

void HttpStream::SetNetworkOptions(const NetworkOptions& options) {
    this->m_networkOptions = options;
}

const HttpParserOptions& HttpStream::GetHttpOptions() const {
    return this->m_httpOptions;
}

HttpParserOptions& HttpStream::GetHttpOptions() {
    return this->m_httpOptions;
}

void HttpStream::SetHttpOptions(const HttpParserOptions& options) {
    this->m_httpOptions = options;
}

TransferEncoding HttpStream::GetTransferEncoding() const {
    return this->m_transferEncoding;
}

void HttpStream::SetTransferEncoding(const TransferEncoding transferEncoding) {

    if ((transferEncoding != TransferEncoding::NONE) && (transferEncoding != TransferEncoding::CHUNKED))
        throw std::invalid_argument("'transferEncoding': Invalid transfer encoding method.");

    this->m_transferEncoding = transferEncoding;

}

std::int32_t HttpStream::Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const Vnet::Sockets::SocketFlags flags) const {
    
    if (this->m_transferEncoding != TransferEncoding::CHUNKED)
        throw InvalidObjectStateException("This function is not supported with the currently selected transfer encoding method.");
    
    if (offset < 0) throw std::out_of_range("'offset' is less than zero.");
    if (offset > data.size()) throw std::out_of_range("'offset' is greater than the buffer size.");
    if (size < 0) throw std::out_of_range("'size' is less than zero.");
    if (size > (data.size() - offset)) throw std::out_of_range("'size' is greater than the buffer size minus 'offset'.");

    if (flags != SocketFlags::NONE)
        throw std::invalid_argument("'flags': This value must be SocketFlags::NONE.");

    std::int32_t sent = 0;

    std::ostringstream stream;
    stream << std::hex << size << "\r\n";
    sent += this->SendData({ reinterpret_cast<const std::uint8_t*>(stream.view().data()), stream.view().length() });

    if (size > 0) sent += this->SendData(data.subspan(offset, size));

    sent += this->SendData({ reinterpret_cast<const std::uint8_t*>("\r\n"), 2 });
    
    return sent;
}

std::int32_t HttpStream::Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {
    return this->Send(data, offset, size, SocketFlags::NONE);
}

std::int32_t HttpStream::Send(const std::span<const std::uint8_t> data, const Vnet::Sockets::SocketFlags flags) const {
    return this->Send(data, 0, data.size(), flags);
}

std::int32_t HttpStream::Send(const std::span<const std::uint8_t> data) const {
    return this->Send(data, 0, data.size(), SocketFlags::NONE);
}

void HttpStream::Send() const {
    this->Send(std::span<const std::uint8_t>());
}

void HttpStream::Send(const HttpRequest& req) const {
    this->SendHttpMessage<HttpRequest>(req);
}

void HttpStream::Send(const HttpResponse& res) const { 
    this->SendHttpMessage<HttpResponse>(res);
}

std::int32_t HttpStream::Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const Vnet::Sockets::SocketFlags flags) const {
    throw std::runtime_error("This function is not supported in the HttpStream class.");
}

std::int32_t HttpStream::Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {
    return this->Receive(data, offset, size, SocketFlags::NONE);
}

std::int32_t HttpStream::Receive(const std::span<std::uint8_t> data, const Vnet::Sockets::SocketFlags flags) const {
    return this->Receive(data, 0, data.size(), flags);
}

std::int32_t HttpStream::Receive(const std::span<std::uint8_t> data) const {
    return this->Receive(data, 0, data.size(), SocketFlags::NONE);
}

TransferEncoding HttpStream::Receive(HttpRequest& req) {
    return this->ReceiveHttpMessage<HttpRequest>(req);
}

TransferEncoding HttpStream::Receive(HttpResponse& res) {
    return this->ReceiveHttpMessage<HttpResponse>(res);
}