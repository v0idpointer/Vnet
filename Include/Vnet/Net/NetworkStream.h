/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETWEB_NET_NETWORKSTREAM_H_
#define _VNETWEB_NET_NETWORKSTREAM_H_

#include <Vnet/Security/SecureConnection.h>

namespace Vnet::Net {

    /**
     * A wrapper class that acts as a common interface
     * for the Socket and SecureConnection classes.
     */
    class VNETWEBAPI NetworkStream {

    private:
        std::shared_ptr<Vnet::Sockets::Socket> m_socket;
        std::shared_ptr<Vnet::Security::SecureConnection> m_ssl;

    public:

        /**
         * Constructs a new NetworkStream object.
         * 
         * @param socket A stream socket.
         * @param ssl A secure connection.
         * @exception std::invalid_argument - The 'socket' parameter is nullptr, or 'socket' is not a stream socket.
         */
        NetworkStream(std::shared_ptr<Vnet::Sockets::Socket> socket, std::shared_ptr<Vnet::Security::SecureConnection> ssl);

        /**
         * Constructs a new NetworkStream object by copying an existing one.
         * 
         * @param stream A NetworkStream object to copy.
         */
        NetworkStream(const NetworkStream& stream);

        NetworkStream(NetworkStream&& stream) noexcept;
        virtual ~NetworkStream(void);

        /**
         * Assigns the value from an existing NetworkStream object to this object.
         * 
         * @param stream A NetworkStream object to copy.
         */
        NetworkStream& operator= (const NetworkStream& stream);
        
        NetworkStream& operator= (NetworkStream&& stream) noexcept;

        /**
         * Returns the underlying Socket object.
         * 
         * @returns A pointer to the socket.
         */
        std::shared_ptr<Vnet::Sockets::Socket> GetSocket(void) const;

        /**
         * Returns the underlying SecureConnection object.
         * 
         * @returns A pointer to the secure connection.
         */
        std::shared_ptr<Vnet::Security::SecureConnection> GetSecureConnection(void) const;

        /**
         * Returns the number of bytes ready to be read.
         * 
         * @returns An integer.
         * @exception SocketException - Failed to get the number of available bytes.
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         */
        std::int32_t GetAvailableBytes(void) const;

        /**
         * Sends data.
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
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         */
        virtual std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const Vnet::Sockets::SocketFlags flags) const;

        /**
         * Sends data.
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
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         */
        virtual std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;

        /**
         * Sends data.
         * 
         * @param data The data to be sent.
         * @param flags Socket flags. This value must be SocketFlags::NONE.
         * @returns The number of bytes sent.
         * @exception std::invalid_argument - The 'flags' parameter is not SocketFlags::NONE.
         * @exception SocketException - Failed to send the data (using Socket).
         * @exception SecurityException - Failed to send the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         */
        virtual std::int32_t Send(const std::span<const std::uint8_t> data, const Vnet::Sockets::SocketFlags flags) const;

        /**
         * Sends data.
         * 
         * @param data The data to be sent.
         * @returns The number of bytes sent.
         * @exception SocketException - Failed to send the data (using Socket).
         * @exception SecurityException - Failed to send the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         */
        virtual std::int32_t Send(const std::span<const std::uint8_t> data) const;

        /**
         * Reads data.
         * 
         * @param data The buffer where the read data will be stored.
         * @param offset The position in the data buffer where to store the read data.
         * @param size The number of bytes to read.
         * @param flags Socket flags. This can be SocketFlags::NONE or SocketFlags::PEEK.
         * @returns The number of bytes read.
         * @exception std::invalid_argument - The 'flags' parameter is not SocketFlags::NONE or SocketFlags::PEEK.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SocketException - Failed to read the data (using Socket).
         * @exception SecurityException - Failed to read the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         */
        virtual std::int32_t Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const Vnet::Sockets::SocketFlags flags) const;

        /**
         * Reads data.
         * 
         * @param data The buffer where the read data will be stored.
         * @param offset The position in the data buffer where to store the read data.
         * @param size The number of bytes to read.
         * @returns The number of bytes read.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SocketException - Failed to read the data (using Socket).
         * @exception SecurityException - Failed to read the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         */
        virtual std::int32_t Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;

        /**
         * Reads data.
         * 
         * @param data The buffer where the read data will be stored.
         * @param flags Socket flags. This can be SocketFlags::NONE or SocketFlags::PEEK.
         * @returns The number of bytes read.
         * @exception std::invalid_argument - The 'flags' parameter is not SocketFlags::NONE or SocketFlags::PEEK.
         * @exception SocketException - Failed to read the data (using Socket).
         * @exception SecurityException - Failed to read the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         */
        virtual std::int32_t Receive(const std::span<std::uint8_t> data, const Vnet::Sockets::SocketFlags flags) const;

        /**
         * Reads data.
         * 
         * @param data The buffer where the read data will be stored.
         * @returns The number of bytes read.
         * @exception SocketException - Failed to read the data (using Socket).
         * @exception SecurityException - Failed to read the data (using SecureConnection).
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         */
        virtual std::int32_t Receive(const std::span<std::uint8_t> data) const;

        /**
         * Shuts down the SSL/TLS connection and closes the socket.
         * 
         * @exception SocketException - An error has occurred while closing the socket.
         * @exception SecurityException - An error has occurred while shutting down the SSL/TLS connection.
         * @exception InvalidObjectStateException - The underlying Socket and/or SecureConnection objects are closed.
         */
        void Close(void);

    };

}

#endif // _VNETWEB_NET_NETWORKSTREAM_H_