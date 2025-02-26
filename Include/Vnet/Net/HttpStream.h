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

#include <utility>
#include <vector>
#include <list>

namespace Vnet::Net {

    /**
     * Represents a network stream specialized in sending and receiving HTTP messages.
     */
    class VNETWEBAPI HttpStream : public NetworkStream {

    private:
        Vnet::Http::HttpParserOptions m_httpOptions;
        TransferEncoding m_transferEncoding;

    public:
        HttpStream(const NetworkStream& stream);
        HttpStream(std::shared_ptr<Vnet::Sockets::Socket> socket, std::shared_ptr<Vnet::Security::SecureConnection> ssl);
        HttpStream(const HttpStream& stream);
        HttpStream(HttpStream&& stream) noexcept;
        virtual ~HttpStream(void);

        HttpStream& operator= (const HttpStream& stream);
        HttpStream& operator= (HttpStream&& stream) noexcept;

    private:
        std::list<std::pair<std::vector<std::uint8_t>, std::size_t>> ReadData(void) const;
        static std::vector<std::uint8_t> ConcatBuffers(const std::list<std::pair<std::vector<std::uint8_t>, std::size_t>>&);
        static std::list<std::pair<std::vector<std::uint8_t>, std::size_t>> ParseChunkedTransferEncoding(const std::span<const std::uint8_t>);
        static Vnet::Http::HttpHeaderCollection ParseHeaders(const std::span<const std::uint8_t>, const Vnet::Http::HttpParserOptions&);
        template <typename T> TransferEncoding ReceiveHttpMessage(T&);

        std::int32_t SendData(const std::span<const std::uint8_t>) const;
        template <typename T> void SendHttpMessage(const T&) const;

    public:

        /**
         * Returns the collection of options used by the HTTP parser.
         * 
         * @returns An HttpParserOptions.
         */
        const Vnet::Http::HttpParserOptions& GetHttpOptions(void) const;
        
        /**
         * Returns the collection of options used by the HTTP parser.
         * 
         * @returns An HttpParserOptions.
         */
        Vnet::Http::HttpParserOptions& GetHttpOptions(void);
        
        /**
         * Sets the collection of options used by the HTTP parser.
         * 
         * @param options
         */
        void SetHttpOptions(const Vnet::Http::HttpParserOptions& options);

        /**
         * Returns the transfer encoding used for sending HTTP messages.
         * 
         * @returns A value from the TransferEncoding enum.
         */
        TransferEncoding GetTransferEncoding(void) const;

        /**
         * Sets the transfer encoding method used for sending HTTP messages.
         * 
         * @param transferEncoding A value from the TransferEncoding enum.
         * @exception std::invalid_argument - The 'transferEncoding' parameter
         * contains an invalid or unsupported transfer encoding method.
         */
        void SetTransferEncoding(const TransferEncoding transferEncoding);

        /**
         * Sends a chunk of data.
         * 
         * @param data The data to be sent.
         * @param offset The position in the data buffer from where to start sending.
         * @param size The number of bytes to send.
         * @param flags Socket flags. This value must be SocketFlags::NONE.
         * @returns The number of bytes sent.
         * @exception std::invalid_argument - The 'flags' parameter is not SocketFlags::NONE.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SocketException - Failed to send the data (using Socket).
         * @exception SecurityException - Failed to send the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed,
         * or the current HttpStream object is not using the chunked transfer encoding.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const Vnet::Sockets::SocketFlags flags) const override;
        
        /**
         * Sends a chunk of data.
         * 
         * @param data The data to be sent.
         * @param offset The position in the data buffer from where to start sending.
         * @param size The number of bytes to send.
         * @returns The number of bytes sent.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SocketException - Failed to send the data (using Socket).
         * @exception SecurityException - Failed to send the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed,
         * or the current HttpStream object is not using the chunked transfer encoding.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const override;
        
        /**
         * Sends a chunk of data.
         * 
         * @param data The data to be sent.
         * @param flags Socket flags. This value must be SocketFlags::NONE.
         * @returns The number of bytes sent.
         * @exception std::invalid_argument - The 'flags' parameter is not SocketFlags::NONE.
         * @exception SocketException - Failed to send the data (using Socket).
         * @exception SecurityException - Failed to send the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed,
         * or the current HttpStream object is not using the chunked transfer encoding.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const Vnet::Sockets::SocketFlags flags) const override;
        
        /**
         * Sends a chunk of data.
         * 
         * @param data The data to be sent.
         * @returns The number of bytes sent.
         * @exception SocketException - Failed to send the data (using Socket).
         * @exception SecurityException - Failed to send the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed,
         * or the current HttpStream object is not using the chunked transfer encoding.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data) const override;

        /**
         * Sends the terminating zero-length chunk.
         * 
         * @exception SocketException - Failed to send the data (using Socket).
         * @exception SecurityException - Failed to send the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed,
         * or the current HttpStream object is not using the chunked transfer encoding.
         */
        void Send(void) const;

        /**
         * Sends an HTTP request message.
         * 
         * @param req An HTTP request message.
         * @exception SocketException - Failed to send the data (using Socket).
         * @exception SecurityException - Failed to send the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         * @exception HttpException - The specified HTTP message contains a Transfer-Encoding header that is 
         * incompatible with the transfer encoding used by the current HttpStream object.
         */
        void Send(const Vnet::Http::HttpRequest& req) const;
        
        /**
         * Sends an HTTP response message.
         * 
         * @param res An HTTP response message.
         * @exception SocketException - Failed to send the data (using Socket).
         * @exception SecurityException - Failed to send the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         * @exception HttpException - The specified HTTP message contains a Transfer-Encoding header that is 
         * incompatible with the transfer encoding used by the current HttpStream object.
         */
        void Send(const Vnet::Http::HttpResponse& res) const;

        /** This function is not supported in the HttpStream class. */
        std::int32_t Receive(const std::span<std::uint8_t>, const std::int32_t, const std::int32_t, const Vnet::Sockets::SocketFlags) const override;

        /** This function is not supported in the HttpStream class. */
        std::int32_t Receive(const std::span<std::uint8_t>, const std::int32_t, const std::int32_t) const override;

        /** This function is not supported in the HttpStream class. */
        std::int32_t Receive(const std::span<std::uint8_t>, const Vnet::Sockets::SocketFlags) const override;

        /** This function is not supported in the HttpStream class. */
        std::int32_t Receive(const std::span<std::uint8_t>) const override;

        /**
         * Reads an HTTP request message.
         * 
         * @param req An HttpRequest object that will store the read request message.
         * @returns A transfer encoding used by the peer to send the request.
         * @exception SocketException - Failed to read the data (using Socket).
         * @exception SecurityException - Failed to read the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         * @exception NetworkException - No data was read from the network, or the read limit was exceeded.
         * @exception HttpException - The read HTTP message uses an invalid or unsupported transfer encoding.
         * @exception HttpParserException - An error has occurred while parsing the HTTP request.
         */
        TransferEncoding Receive(Vnet::Http::HttpRequest& req);

        /**
         * Reads an HTTP response message.
         * 
         * @param res An HttpResponse object that will store the read response message.
         * @returns A transfer encoding used by the peer to send the response.
         * @exception SocketException - Failed to read the data (using Socket).
         * @exception SecurityException - Failed to read the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         * @exception NetworkException - No data was read from the network, or the read limit was exceeded.
         * @exception HttpException - The read HTTP message uses an invalid or unsupported transfer encoding.
         * @exception HttpParserException - An error has occurred while parsing the HTTP response.
         */
        TransferEncoding Receive(Vnet::Http::HttpResponse& res);

    };

}

#endif // _VNETWEB_NET_HTTPSTREAM_H_