/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETCORE_SOCKETS_SOCKET_H_
#define _VNETCORE_SOCKETS_SOCKET_H_

#include <Vnet/Exports.h>
#include <Vnet/Sockets/AddressFamily.h>
#include <Vnet/Sockets/SocketType.h>
#include <Vnet/Sockets/Protocol.h>
#include <Vnet/Sockets/ShutdownSocket.h>
#include <Vnet/Sockets/ISocketAddress.h>
#include <Vnet/Sockets/SocketFlags.h>
#include <Vnet/Sockets/PollEvent.h>

#include <cstdint>
#include <span>

namespace Vnet::Sockets {

#ifdef VNET_PLATFORM_WINDOWS
    typedef std::uint64_t NativeSocket_t;
    constexpr NativeSocket_t INVALID_SOCKET_HANDLE = (NativeSocket_t)(~0);
#else
    typedef std::int32_t NativeSocket_t;
    constexpr NativeSocket_t INVALID_SOCKET_HANDLE = -1;
#endif

    /**
     * Represents a Berkeley (BSD) socket.
     */
    class VNETCOREAPI Socket {

    private:
        AddressFamily m_af;
        SocketType m_type;
        Protocol m_proto;
        NativeSocket_t m_socket;
        bool m_blocking;

    private:
        Socket(const NativeSocket_t socket, const AddressFamily af, const SocketType type, const Protocol proto);

    public:

        /**
         * Constructs a new Socket object.
         * 
         * @param af A value from the AddressFamily enum.
         * @param type A value from the SocketType enum.
         * @param proto A value from the Protocol enum.
         * @exception SocketException
         */
        Socket(const AddressFamily af, const SocketType type, const Protocol proto);

        Socket(const Socket&) = delete;
        Socket(Socket&& socket) noexcept;
        virtual ~Socket(void);

        Socket& operator= (const Socket&) = delete;        
        Socket& operator= (Socket&& socket) noexcept;
        
        /**
         * Compares this Socket object with another for equality.
         * 
         * @param socket A Socket to compare with.
         * @returns true if the Socket objects are equal; otherwise, false.
         */
        bool operator== (const Socket& socket) const;

        /**
         * Returns the socket's address family.
         * 
         * @returns An AddressFamily.
         */
        AddressFamily GetAddressFamily(void) const;

        /**
         * Returns the type of the socket.
         * 
         * @returns A SocketType.
         */
		SocketType GetSocketType(void) const;

        /**
         * Returns the protocol used by the socket.
         * 
         * @returns A Protocol.
         */
		Protocol GetProtocol(void) const;

        /**
         * Returns the native socket handle.
         * 
         * @note DO NOT MANUALLY FREE THIS HANDLE!
         * 
         * This handle is managed by the current Socket object,
         * and manually freeing it will cause undefined behavior that can break Vnetcore.
         * 
         * @returns A NativeSocket_t
         */
		NativeSocket_t GetNativeSocketHandle(void) const;

        /**
         * Closes the socket.
         * 
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        void Close(void);

        /**
         * Disables reads or writes on the Socket.
         * 
         * @param how What operation to disable.
         * @exception std::invalid_argument - The 'how' parameter contains an invalid value.
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        void Shutdown(const ShutdownSocket how) const;

        /**
         * Associates a local address with the socket.
         * 
         * @param sockaddr A reference to an ISocketAddress that stores the local address.
         * @exception std::invalid_argument - The 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        void Bind(const ISocketAddress& sockaddr) const;

        /**
         * Establishes a connection to a remote socket.
         * 
         * @param sockaddr A reference to an ISocketAddress that stores the remote socket's address.
         * @exception std::invalid_argument - The 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        void Connect(const ISocketAddress& sockaddr) const;


        /**
         * Places the socket in a listening state.
         * 
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        void Listen(void) const;

        /**
         * Places the socket in a listening state.
         * 
         * @param backlog The maximum length of the pending connections queue.
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        void Listen(const std::int32_t backlog) const;

        /**
         * Accepts a new connection.
         * 
         * @returns A newly created Socket for the new connection.
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        Socket Accept(void) const;

        /**
         * Sends data.
         * 
         * @param data The data to be sent.
         * @param offset The position in the data buffer from where to start sending.
         * @param size The number of bytes to send.
         * @param flags One or more values, bitwise OR-ed together, from the SocketFlags enum.
         * @returns The number of bytes sent.
         * @exception std::invalid_argument - The 'flags' parameter contains an invalid socket flag.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SocketException - Failed to send the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const;
        
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
         * @exception SocketException - Failed to send the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;
        
        /**
         * Sends data.
         * 
         * @param data The data to be sent.
         * @param flags One or more values, bitwise OR-ed together, from the SocketFlags enum.
         * @returns The number of bytes sent.
         * @exception std::invalid_argument - The 'flags' parameter contains an invalid socket flag.
         * @exception SocketException - Failed to send the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const SocketFlags flags) const;
        
        /**
         * Sends data.
         * 
         * @param data The data to be sent.
         * @returns The number of bytes sent.
         * @exception SocketException - Failed to send the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data) const;

        /**
         * Reads data.
         * 
         * @param data The buffer where the read data will be stored.
         * @param offset The position in the data buffer where to store the read data.
         * @param size The number of bytes to read.
         * @param flags One or more values, bitwise OR-ed together, from the SocketFlags enum.
         * @returns The number of bytes read.
         * @exception std::invalid_argument - The 'flags' parameter contains an invalid socket flag.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SocketException - Failed to read the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const;
        
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
         * @exception SocketException - Failed to read the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;
        
        /**
         * Reads data.
         * 
         * @param data The buffer where the read data will be stored.
         * @param flags One or more values, bitwise OR-ed together, from the SocketFlags enum.
         * @returns The number of bytes read.
         * @exception std::invalid_argument - The 'flags' parameter contains an invalid socket flag.
         * @exception SocketException - Failed to read the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data, const SocketFlags flags) const;
        
        /**
         * Reads data.
         * 
         * @param data The buffer where the read data will be stored.
         * @returns The number of bytes read.
         * @exception SocketException - Failed to read the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data) const;

        /**
         * Sends a datagram.
         * 
         * @param data The data to be sent.
         * @param offset The position in the data buffer from where to start sending.
         * @param size The number of bytes to send.
         * @param flags One or more values, bitwise OR-ed together, from the SocketFlags enum.
         * @param sockaddr A reference to an ISocketAddress that stores the datagram's destination address.
         * @returns The number of bytes sent.
         * @exception std::invalid_argument - The 'flags' parameter contains an invalid socket flag,
         * or the 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SocketException - Failed to send the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t SendTo(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags, const ISocketAddress& sockaddr) const;
        
        /**
         * Sends a datagram.
         * 
         * @param data The data to be sent.
         * @param offset The position in the data buffer from where to start sending.
         * @param size The number of bytes to send.
         * @param sockaddr A reference to an ISocketAddress that stores the datagram's destination address.
         * @returns The number of bytes sent.
         * @exception std::invalid_argument - The 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SocketException - Failed to send the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t SendTo(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const ISocketAddress& sockaddr) const;
        
        /**
         * Sends a datagram.
         * 
         * @param data The data to be sent.
         * @param flags One or more values, bitwise OR-ed together, from the SocketFlags enum.
         * @param sockaddr A reference to an ISocketAddress that stores the datagram's destination address.
         * @returns The number of bytes sent.
         * @exception std::invalid_argument - The 'flags' parameter contains an invalid socket flag,
         * or the 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception SocketException - Failed to send the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t SendTo(const std::span<const std::uint8_t> data, const SocketFlags flags, const ISocketAddress& sockaddr) const;
        
        /**
         * Sends a datagram.
         * 
         * @param data The data to be sent.
         * @param sockaddr A reference to an ISocketAddress that stores the datagram's destination address.
         * @returns The number of bytes sent.
         * @exception std::invalid_argument - The 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception SocketException - Failed to send the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t SendTo(const std::span<const std::uint8_t> data, const ISocketAddress& sockaddr) const;

        /**
         * Reads a datagram.
         * 
         * @param data The buffer where the read data will be stored.
         * @param offset The position in the data buffer where to store the read data.
         * @param size The number of bytes to read.
         * @param flags One or more values, bitwise OR-ed together, from the SocketFlags enum.
         * @param sockaddr A reference to an ISocketAddress that will store the datagram's source address.
         * @returns The number of bytes read.
         * @exception std::invalid_argument - The 'flags' parameter contains an invalid socket flag,
         * or the 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SocketException - Failed to read the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t ReceiveFrom(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags, ISocketAddress& sockaddr) const;
        
        /**
         * Reads a datagram.
         * 
         * @param data The buffer where the read data will be stored.
         * @param offset The position in the data buffer where to store the read data.
         * @param size The number of bytes to read.
         * @param sockaddr A reference to an ISocketAddress that will store the datagram's source address.
         * @returns The number of bytes read.
         * @exception std::invalid_argument - The 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SocketException - Failed to read the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t ReceiveFrom(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, ISocketAddress& sockaddr) const;

        /**
         * Reads a datagram.
         * 
         * @param data The buffer where the read data will be stored.
         * @param flags One or more values, bitwise OR-ed together, from the SocketFlags enum.
         * @param sockaddr A reference to an ISocketAddress that will store the datagram's source address.
         * @returns The number of bytes read.
         * @exception std::invalid_argument - The 'flags' parameter contains an invalid socket flag,
         * or the 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception SocketException - Failed to read the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t ReceiveFrom(const std::span<std::uint8_t> data, const SocketFlags flags, ISocketAddress& sockaddr) const;

        /**
         * Reads a datagram.
         * 
         * @param data The buffer where the read data will be stored.
         * @param sockaddr A reference to an ISocketAddress that will store the datagram's source address.
         * @returns The number of bytes read.
         * @exception std::invalid_argument - The 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception SocketException - Failed to read the data.
         * @exception InvalidObjectStateException - The socket is closed.
         */
        std::int32_t ReceiveFrom(const std::span<std::uint8_t> data, ISocketAddress& sockaddr) const;

        /**
         * Gets the local socket's address.
         * 
         * @param sockaddr A reference to an ISocketAddress that will store the socket address.
         * @exception std::invalid_argument - The 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        void GetSocketAddress(ISocketAddress& sockaddr) const;

        /**
         * Gets the remote socket's address.
         * 
         * @param sockaddr A reference to an ISocketAddress that will store the socket address.
         * @exception std::invalid_argument - The 'sockaddr' parameter points to an unknown ISocketAddress implementation.
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        void GetPeerAddress(ISocketAddress& sockaddr) const;

        /**
         * Determines the status of the socket.
         * 
         * @param pollEvent A value from the PollEvent enum.
         * @param timeout The time (in milliseconds) to wait.
         * @returns A boolean representing the status of the socket.
         * @exception std::invalid_argument - The 'pollEvent' parameter contains an invalid value.
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        bool Poll(const PollEvent pollEvent, const std::int32_t timeout) const;

        /**
         * Returns the number of bytes ready to be read.
         * 
         * @returns An integer.
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        std::int32_t GetAvailableBytes(void) const;

        /**
         * Checks if the socket is in blocking mode.
         * 
         * @returns true if the socket is blocking; otherwise, false.
         */
        bool IsBlocking(void) const;

        /**
         * Sets the blocking mode of the socket.
         * 
         * @param blocking true for blocking mode, or false for non-blocking mode.
         * @exception SocketException
         * @exception InvalidObjectStateException
         */
        void SetBlocking(const bool blocking);

    };

}

#endif // _VNETCORE_SOCKETS_SOCKET_H_