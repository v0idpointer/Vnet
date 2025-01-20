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
        SecureConnection(void);
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
         * Returns the local X.509 certificate.
         * 
         * @returns An optional X.509 certificate.
         * @exception std::runtime_error - The secure connection is not valid.
         * @exception SecurityException
         */
        std::optional<Cryptography::Certificates::Certificate> GetCertificate(void) const;

        /**
         * Returns the peer's X.509 certificate.
         * 
         * @returns An optional X.509 certificate.
         * @exception std::runtime_error - The secure connection is not valid.
         * @exception SecurityException
         */
        std::optional<Cryptography::Certificates::Certificate> GetPeerCertificate(void) const;

        /**
         * Returns the number of bytes ready to be read.
         * 
         * @exception std::runtime_error - The secure connection is not valid.
         */
        std::int32_t GetAvailableBytes(void) const;

        /**
         * Sends data over a secure connection.
         * 
         * @param data Data to be sent.
         * @param offset The position in the data buffer from where to start sending.
         * @param size The number of bytes to send.
         * @param flags Socket flags. This value must be SocketFlags::NONE.
         * @returns The number of bytes sent.
         * @exception std::runtime_error - The secure connection is not valid.
         * @exception std::invalid_argument - The 'flags' parameter is not SocketFlags::NONE.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SecurityException - Failed to send the data.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const Sockets::SocketFlags flags) const;

        /**
         * Sends data over a secure connection.
         * 
         * @param data Data to be sent.
         * @param offset The position in the data buffer from where to start sending.
         * @param size The number of bytes to send.
         * @returns The number of bytes sent.
         * @exception std::runtime_error - The secure connection is not valid.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SecurityException - Failed to send the data.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;

        /**
         * Sends data over a secure connection.
         * 
         * @param data Data to be sent.
         * @param flags Socket flags. This value must be SocketFlags::NONE.
         * @returns The number of bytes sent.
         * @exception std::runtime_error - The secure connection is not valid.
         * @exception std::invalid_argument - The 'flags' parameter is not SocketFlags::NONE.
         * @exception SecurityException - Failed to send the data.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data, const Sockets::SocketFlags flags) const;

        /**
         * Sends data over a secure connection.
         * 
         * @param data Data to be sent.
         * @returns The number of bytes sent.
         * @exception std::runtime_error - The secure connection is not valid.
         * @exception SecurityException - Failed to send the data.
         */
        std::int32_t Send(const std::span<const std::uint8_t> data) const;
        
        /**
         * Reads data from a secure connection.
         * 
         * @param data Buffer where the read data will be stored.
         * @param offset The position in the data buffer where to store the read data.
         * @param size The number of bytes to read.
         * @param flags Socket flags. This can be SocketFlags::NONE or SocketFlags::PEEK.
         * @returns The number of bytes read.
         * @exception std::runtime_error - The secure connection is not valid.
         * @exception std::invalid_argument - The 'flags' parameter is not SocketFlags::NONE or SocketFlags::PEEK.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SecurityException - Failed to read the data.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const Sockets::SocketFlags flags) const;

        /**
         * Reads data from a secure connection.
         * 
         * @param data Buffer where the read data will be stored.
         * @param offset The position in the data buffer where to store the read data.
         * @param size The number of bytes to read.
         * @returns The number of bytes read.
         * @exception std::runtime_error - The secure connection is not valid.
         * @exception std::out_of_range - The 'offset' parameter is less than zero, or
         * 'offset' is greater than the buffer size, or the 'size' parameter is less than zero,
         * or 'size' is greater than the buffer size minus 'offset'.
         * @exception SecurityException - Failed to read the data.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;

        /**
         * Reads data from a secure connection.
         * 
         * @param data Buffer where the read data will be stored.
         * @param flags Socket flags. This can be SocketFlags::NONE or SocketFlags::PEEK.
         * @returns The number of bytes read.
         * @exception std::runtime_error - The secure connection is not valid.
         * @exception std::invalid_argument - The 'flags' parameter is not SocketFlags::NONE or SocketFlags::PEEK.
         * @exception SecurityException - Failed to read the data.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data, const Sockets::SocketFlags flags) const;

        /**
         * Reads data from a secure connection.
         * 
         * @param data Buffer where the read data will be stored.
         * @returns The number of bytes read.
         * @exception std::runtime_error - The secure connection is not valid.
         * @exception SecurityException - Failed to read the data.
         */
        std::int32_t Receive(const std::span<std::uint8_t> data) const;

        /**
         * Shuts down the SSL/TLS connection.
         * 
         * After this function call, the current SecureConnection 
         * object will become invalid.
         * 
         * @exception std::runtime_error - The secure connection is not valid.
         * @exception SecurityException
         */
        void Close(void);

    private:
        static NativeSecureConnection_t CreateConnection(const SecurityContext& ctx, const Sockets::NativeSocket_t socket);

    public:
        static SecureConnection Connect(const SecurityContext& ctx, const Sockets::Socket& socket);
        static SecureConnection Connect(const SecurityContext& ctx, const Sockets::NativeSocket_t socket);

        static SecureConnection Accept(const SecurityContext& ctx, const Sockets::Socket& socket);
        static SecureConnection Accept(const SecurityContext& ctx, const Sockets::NativeSocket_t socket);

    };

}

#endif // _VNETSEC_SECURITY_SECURECONNECTION_H_