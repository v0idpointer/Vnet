/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_SECURITY_SECURECONNECTION_H_
#define _VNETSEC_SECURITY_SECURECONNECTION_H_

#include <Vnet/Security/SecurityContext.h>
#include <Vnet/Security/ConnectFlags.h>
#include <Vnet/Security/AcceptFlags.h>
#include <Vnet/Sockets/Socket.h>

#include <string_view>
#include <optional>

struct ssl_st;

namespace Vnet::Security { 

    typedef ssl_st* NativeSecureConnection_t;
    constexpr NativeSecureConnection_t INVALID_SECURE_CONNECTION_HANDLE = nullptr;

    /**
     * Represents a secure connection (using SSL/TLS) between
     * a client and a server.
     */
    class VNETSECURITYAPI SecureConnection {

    private:
        NativeSecureConnection_t m_ssl;

    private:
        SecureConnection(NativeSecureConnection_t const ssl);

    public:
        SecureConnection(const SecureConnection&) = delete;
        SecureConnection(SecureConnection&& conn) noexcept;
        virtual ~SecureConnection(void);

        SecureConnection& operator= (const SecureConnection&) = delete;
        SecureConnection& operator= (SecureConnection&& conn) noexcept;

        /**
         * Returns the native secure connection handle.
         * 
         * @note DO NOT MANUALLY FREE THIS HANDLE!
         * 
         * This handle is managed by the current SecureConnection object,
         * and manually freeing it will cause undefined behavior that can break Vnetsec.
         * 
         * @returns A NativeSecureConnection_t
         */
        NativeSecureConnection_t GetNativeSecureConnectionHandle(void) const;

        /**
         * Returns the security protocol used in the secure connection.
         * 
         * @returns A value from the SecurityProtocol enum.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        SecurityProtocol GetSecurityProtocol(void) const;

        /**
         * Returns the local X.509 certificate.
         * 
         * @returns An optional X.509 certificate.
         * @exception SecurityException - Failed to retrieve an X.509 certificate.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        std::optional<Cryptography::Certificates::Certificate> GetCertificate(void) const;

        /**
         * Returns the peer's X.509 certificate.
         * 
         * @returns An optional X.509 certificate.
         * @exception SecurityException - Failed to retrieve an X.509 certificate.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        std::optional<Cryptography::Certificates::Certificate> GetPeerCertificate(void) const;

        /**
         * Returns the number of bytes ready to be read.
         * 
         * @note This function will block if there is no data to be read, instead of returning zero.
         * To avoid this behavior, set the socket (the socket used to open this secure connection)
         * to non-blocking mode before calling this function.
         * 
         * @returns An integer.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        std::int32_t GetAvailableBytes(void) const;

        /**
         * Sends data over the secure connection.
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
         * @exception SecurityException - Failed to send the data.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const Sockets::SocketFlags flags) const;

        /**
         * Sends data over the secure connection.
         * 
         * @param data The data to be sent.
         * @param offset The position in the data buffer from where to start sending.
         * @param size The number of bytes to send.
         * @returns The number of bytes sent.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SecurityException - Failed to send the data.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;

        /**
         * Sends data over the secure connection.
         * 
         * @param data The data to be sent.
         * @param flags Socket flags. This value must be SocketFlags::NONE.
         * @returns The number of bytes sent.
         * @exception std::invalid_argument - The 'flags' parameter is not SocketFlags::NONE.
         * @exception SecurityException - Failed to send the data.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const Sockets::SocketFlags flags) const;

        /**
         * Sends data over the secure connection.
         * 
         * @param data The data to be sent.
         * @returns The number of bytes sent.
         * @exception SecurityException - Failed to send the data.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data) const;
        
        /**
         * Reads data from the secure connection.
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
         * @exception SecurityException - Failed to read the data.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const Sockets::SocketFlags flags) const;

        /**
         * Reads data from the secure connection.
         * 
         * @param data The buffer where the read data will be stored.
         * @param offset The position in the data buffer where to store the read data.
         * @param size The number of bytes to read.
         * @returns The number of bytes read.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SecurityException - Failed to read the data.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;

        /**
         * Reads data from the secure connection.
         * 
         * @param data The buffer where the read data will be stored.
         * @param flags Socket flags. This can be SocketFlags::NONE or SocketFlags::PEEK.
         * @returns The number of bytes read.
         * @exception std::invalid_argument - The 'flags' parameter is not SocketFlags::NONE or SocketFlags::PEEK.
         * @exception SecurityException - Failed to read the data.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data, const Sockets::SocketFlags flags) const;

        /**
         * Reads data from the secure connection.
         * 
         * @param data The buffer where the read data will be stored.
         * @returns The number of bytes read.
         * @exception SecurityException - Failed to read the data.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data) const;

        /**
         * Shuts down the SSL/TLS connection.
         * 
         * After this function call, the current SecureConnection 
         * object will become invalid.
         * 
         * @exception SecurityException - Failed to shut down the secure connection.
         * @exception InvalidObjectStateException - The secure connection is closed.
         */
        void Close(void);

    private:
        static NativeSecureConnection_t CreateConnection(const SecurityContext& ctx, const Sockets::NativeSocket_t socket);

    public:

        /**
         * Initiates a new secure connection.
         * 
         * This function is used by client-side applications.
         * 
         * @param ctx A client security context.
         * @param socket A socket.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a client security context,
         * or the 'socket' parameter contains an invalid socket.
         * @exception SecurityException
         */
        static SecureConnection Connect(const SecurityContext& ctx, const Sockets::Socket& socket);
        
        /**
         * Initiates a new secure connection.
         * 
         * This function is used by client-side applications.
         * 
         * @param ctx A client security context.
         * @param socket A socket handle.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a client security context,
         * or the 'socket' parameter contains an invalid socket handle.
         * @exception SecurityException
         */
        static SecureConnection Connect(const SecurityContext& ctx, const Sockets::NativeSocket_t socket);

        /**
         * Initiates a new secure connection.
         * 
         * This function is used by client-side applications.
         * 
         * @param hostname An optional string containing a hostname for the Server Name Indication (SNI), a TLS extension.
         * @param ctx A client security context.
         * @param socket A socket.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a client security context,
         * or the 'socket' parameter contains an invalid socket, or the 'hostname' parameter is an empty string.
         * @exception SecurityException
         */
        static SecureConnection Connect(const std::optional<std::string_view> hostname, const SecurityContext& ctx, const Sockets::Socket& socket);

        /**
         * Initiates a new secure connection.
         * 
         * This function is used by client-side applications.
         * 
         * @param hostname An optional string containing a hostname for the Server Name Indication (SNI), a TLS extension.
         * @param ctx A client security context.
         * @param socket A socket handle.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a client security context,
         * or the 'socket' parameter contains an invalid socket handle, or the 'hostname' parameter is an empty string.
         * @exception SecurityException
         */
        static SecureConnection Connect(const std::optional<std::string_view> hostname, const SecurityContext& ctx, const Sockets::NativeSocket_t socket);

        /**
         * Initiates a new secure connection.
         * 
         * This function is used by client-side applications.
         * 
         * @param ctx A client security context.
         * @param socket A socket.
         * @param flags One or more values, bitwise OR-ed together, from the ConnectFlags enum.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a client security context,
         * or the 'socket' parameter contains an invalid socket, or the 'flags' parameter contains
         * an invalid value.
         * @exception SecurityException
         */
        static SecureConnection Connect(const SecurityContext& ctx, const Sockets::Socket& socket, const ConnectFlags flags);

        /**
         * Initiates a new secure connection.
         * 
         * This function is used by client-side applications.
         * 
         * @param ctx A client security context.
         * @param socket A socket handle.
         * @param flags One or more values, bitwise OR-ed together, from the ConnectFlags enum.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a client security context,
         * or the 'socket' parameter contains an invalid socket handle, or the 'flags' parameter contains
         * an invalid value.
         * @exception SecurityException
         */
        static SecureConnection Connect(const SecurityContext& ctx, const Sockets::NativeSocket_t socket, const ConnectFlags flags);

        /**
         * Initiates a new secure connection.
         * 
         * This function is used by client-side applications.
         * 
         * @param hostname An optional string containing a hostname for the Server Name Indication (SNI), a TLS extension.
         * @param ctx A client security context.
         * @param socket A socket.
         * @param flags One or more values, bitwise OR-ed together, from the ConnectFlags enum.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a client security context,
         * or the 'socket' parameter contains an invalid socket, or the 'flags' parameter contains
         * an invalid value, or the 'hostname' parameter is an empty string.
         * @exception SecurityException
         */
        static SecureConnection Connect(const std::optional<std::string_view> hostname, const SecurityContext& ctx, const Sockets::Socket& socket, const ConnectFlags flags);

        /**
         * Initiates a new secure connection.
         * 
         * This function is used by client-side applications.
         * 
         * @param hostname An optional string containing a hostname for the Server Name Indication (SNI), a TLS extension.
         * @param ctx A client security context.
         * @param socket A socket handle.
         * @param flags One or more values, bitwise OR-ed together, from the ConnectFlags enum.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a client security context,
         * or the 'socket' parameter contains an invalid socket handle, or the 'flags' parameter contains
         * an invalid value, or the 'hostname' parameter is an empty string.
         * @exception SecurityException
         */
        static SecureConnection Connect(const std::optional<std::string_view> hostname, const SecurityContext& ctx, const Sockets::NativeSocket_t socket, const ConnectFlags flags);

        /**
         * Accepts a new secure connection.
         * 
         * This function is used by server-side applications.
         * 
         * @param ctx A server security context.
         * @param socket A socket.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a server security context,
         * or the 'socket' parameter contains an invalid socket.
         * @exception SecurityException
         */
        static SecureConnection Accept(const SecurityContext& ctx, const Sockets::Socket& socket);

        /**
         * Accepts a new secure connection.
         * 
         * This function is used by server-side applications.
         * 
         * @param ctx A server security context.
         * @param socket A socket handle.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a server security context,
         * or the 'socket' parameter contains an invalid socket handle.
         * @exception SecurityException
         */
        static SecureConnection Accept(const SecurityContext& ctx, const Sockets::NativeSocket_t socket);

        /**
         * Accepts a new secure connection.
         * 
         * This function is used by server-side applications.
         * 
         * @param ctx A server security context.
         * @param socket A socket.
         * @param flags One or more values, bitwise OR-ed together, from the AcceptFlags enum.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a server security context,
         * or the 'socket' parameter contains an invalid socket, or the 'flags' parameter contains
         * an invalid value.
         * @exception SecurityException
         */
        static SecureConnection Accept(const SecurityContext& ctx, const Sockets::Socket& socket, const AcceptFlags flags);

        /**
         * Accepts a new secure connection.
         * 
         * This function is used by server-side applications.
         * 
         * @param ctx A server security context.
         * @param socket A socket handle.
         * @param flags One or more values, bitwise OR-ed together, from the AcceptFlags enum.
         * @returns A new secure connection.
         * @exception std::invalid_argument - The 'ctx' parameter is not a server security context,
         * or the 'socket' parameter contains an invalid socket handle, or the 'flags' parameter contains
         * an invalid value.
         * @exception SecurityException
         */
        static SecureConnection Accept(const SecurityContext& ctx, const Sockets::NativeSocket_t socket, const AcceptFlags flags);

    };

}

#endif // _VNETSEC_SECURITY_SECURECONNECTION_H_