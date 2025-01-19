/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Security/SecureConnection.h>
#include <Vnet/Security/SecurityException.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

using namespace Vnet::Security;
using namespace Vnet::Sockets;

SecureConnection::SecureConnection(NativeSecureConnection_t const ssl) : m_ssl(ssl) { }

SecureConnection::SecureConnection() : m_ssl(INVALID_SECURE_CONNECTION_HANDLE) { }

SecureConnection::SecureConnection(SecureConnection&& conn) noexcept : m_ssl(INVALID_SECURE_CONNECTION_HANDLE) {
    this->operator= (std::move(conn));
}

SecureConnection::~SecureConnection() { 

    if (this->m_ssl != INVALID_SECURE_CONNECTION_HANDLE) {
        SSL_free(this->m_ssl);
        this->m_ssl = INVALID_SECURE_CONNECTION_HANDLE;
    }

}

SecureConnection& SecureConnection::operator= (SecureConnection&& conn) noexcept {

    if (this != &conn) {

        if (this->m_ssl != INVALID_SECURE_CONNECTION_HANDLE) {
            SSL_free(this->m_ssl);
            this->m_ssl = INVALID_SECURE_CONNECTION_HANDLE;
        }

        this->m_ssl = conn.m_ssl;
        conn.m_ssl = INVALID_SECURE_CONNECTION_HANDLE;

    }

    return static_cast<SecureConnection&>(*this);
}

NativeSecureConnection_t SecureConnection::GetNativeSecureConnectionHandle() const {
    return this->m_ssl;
}

std::int32_t SecureConnection::GetAvailableBytes() const {
    
    if (this->m_ssl == INVALID_SECURE_CONNECTION_HANDLE)
        throw std::runtime_error("Invalid secure connection.");

    SSL_peek(this->m_ssl, nullptr, 0);

    return SSL_pending(this->m_ssl);
}

std::int32_t SecureConnection::Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {

    if (this->m_ssl == INVALID_SECURE_CONNECTION_HANDLE)
        throw std::runtime_error("Invalid secure connection.");

    if (offset < 0) throw std::out_of_range("'offset' is less than zero.");
    if (offset > data.size()) throw std::out_of_range("'offset' is greater than the buffer size.");
    if (size < 0) throw std::out_of_range("'size' is less that zero.");
    if (size > (data.size() - offset)) throw std::out_of_range("'size' is greater than the buffer size minus 'offset'.");

    const char* const buffer = reinterpret_cast<const char*>(data.data() + offset);

    std::int32_t sent = SSL_write(this->m_ssl, buffer, size);
    if (sent <= 0) throw SecurityException(ERR_get_error());

    return sent;
}

std::int32_t SecureConnection::Send(const std::span<const std::uint8_t> data) const {
    return this->Send(data, 0, data.size());
}

std::int32_t SecureConnection::Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {

    if (this->m_ssl == INVALID_SECURE_CONNECTION_HANDLE)
        throw std::runtime_error("Invalid secure connection.");

    if (offset < 0) throw std::out_of_range("'offset' is less than zero.");
    if (offset > data.size()) throw std::out_of_range("'offset' is greater than the buffer size.");
    if (size < 0) throw std::out_of_range("'size' is less that zero.");
    if (size > (data.size() - offset)) throw std::out_of_range("'size' is greater than the buffer size minus 'offset'.");

    char* const buffer = reinterpret_cast<char*>(data.data() + offset);

    std::int32_t read = SSL_read(this->m_ssl, buffer, size);
    if (read <= 0) throw SecurityException(ERR_get_error());

    return read;
}

std::int32_t SecureConnection::Receive(const std::span<std::uint8_t> data) const {
    return this->Receive(data, 0, data.size());
}

void SecureConnection::Close() {

    if (this->m_ssl == INVALID_SECURE_CONNECTION_HANDLE)
        throw std::runtime_error("Invalid secure connection.");

    std::int32_t result = SSL_shutdown(this->m_ssl);

    if (result == 0) 
        result = SSL_shutdown(this->m_ssl);

    if (result != 1) {
        SSL_free(this->m_ssl);
        throw SecurityException(ERR_get_error());
    }

    SSL_free(this->m_ssl);
    this->m_ssl = INVALID_SECURE_CONNECTION_HANDLE;

}

NativeSecureConnection_t SecureConnection::CreateConnection(const SecurityContext& ctx, const NativeSocket_t socket) {

    if (ctx.GetNativeSecurityContextHandle() == INVALID_SECURITY_CONTEXT_HANDLE)
        throw std::invalid_argument("'ctx': Invalid security context.");

    if (socket == INVALID_SOCKET_HANDLE)
        throw std::invalid_argument("'socket': Invalid socket.");

    SSL* ssl = SSL_new(ctx.GetNativeSecurityContextHandle());
    if (ssl == nullptr) throw SecurityException(ERR_get_error());

    if (SSL_set_fd(ssl, socket) != 1) {
        SSL_free(ssl);
        throw SecurityException(ERR_get_error());
    }

    return ssl;
}

SecureConnection SecureConnection::Connect(const SecurityContext& ctx, const Socket& socket) {
    return SecureConnection::Connect(ctx, socket.GetNativeSocketHandle());
}

SecureConnection SecureConnection::Connect(const SecurityContext& ctx, const NativeSocket_t socket) {

    NativeSecureConnection_t ssl = SecureConnection::CreateConnection(ctx, socket);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        throw SecurityException(ERR_get_error());
    }

    return { ssl };
}

SecureConnection SecureConnection::Accept(const SecurityContext& ctx, const Socket& socket) {
    return SecureConnection::Accept(ctx, socket.GetNativeSocketHandle());
}

SecureConnection SecureConnection::Accept(const SecurityContext& ctx, const NativeSocket_t socket) {

    NativeSecureConnection_t ssl = SecureConnection::CreateConnection(ctx, socket);

    std::uint8_t sessionId[32] = { 0 };
    RAND_bytes(sessionId, sizeof(sessionId));

    if (SSL_set_session_id_context(ssl, sessionId, sizeof(sessionId)) != 1) {
        SSL_free(ssl);
        throw SecurityException(ERR_get_error());
    }

    if (SSL_accept(ssl) != 1) {
        SSL_free(ssl);
        throw SecurityException(ERR_get_error());
    }

    return { ssl };
}