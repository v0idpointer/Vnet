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

        NativeSecureConnection_t GetNativeSecureConnectionHandle(void) const;

        std::int32_t GetAvailableBytes(void) const;

        std::int32_t Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;
        std::int32_t Send(const std::span<const std::uint8_t> data) const;
        
        std::int32_t Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const;
        std::int32_t Receive(const std::span<std::uint8_t> data) const;

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