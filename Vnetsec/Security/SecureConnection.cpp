/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/Security/SecureConnection.h>
#include <Vnet/Security/SecurityException.h>
#include <Vnet/Cryptography/Certificates/Certificate.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

using namespace Vnet::Security;
using namespace Vnet::Sockets;
using namespace Vnet::Cryptography::Certificates;

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

SecurityProtocol SecureConnection::GetSecurityProtocol() const {

    if (this->m_ssl == INVALID_SECURE_CONNECTION_HANDLE)
        throw std::runtime_error("Invalid secure connection.");

    switch (SSL_version(this->m_ssl)) {

    case SSL2_VERSION:
        return SecurityProtocol::SSL_2_0;

    case SSL3_VERSION:
        return SecurityProtocol::SSL_3_0;

    case TLS1_VERSION:
        return SecurityProtocol::TLS_1_0;

    case TLS1_1_VERSION:
        return SecurityProtocol::TLS_1_1;

    case TLS1_2_VERSION:
        return SecurityProtocol::TLS_1_2;

    case TLS1_3_VERSION:
        return SecurityProtocol::TLS_1_3;

    default:
        return SecurityProtocol::UNSPECIFIED;

    }

}

std::optional<Certificate> SecureConnection::GetCertificate() const {

    if (this->m_ssl == INVALID_SECURE_CONNECTION_HANDLE)
        throw std::runtime_error("Invalid secure connection.");

    X509* cert = SSL_get_certificate(this->m_ssl);
    if (cert == nullptr) return std::nullopt;

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) 
        throw SecurityException(ERR_get_error());

    if (PEM_write_bio_X509(bio, cert) != 1) {
        BIO_free(bio);
        throw SecurityException(ERR_get_error());
    }

    const char* str = nullptr;
    std::size_t len = BIO_get_mem_data(bio, &str);
    std::string pem = { str, len };

    BIO_free(bio);
    bio = nullptr;
    cert = nullptr;

    return Certificate::LoadCertificateFromPEM(pem, std::nullopt);
}

std::optional<Certificate> SecureConnection::GetPeerCertificate() const {
    
    if (this->m_ssl == INVALID_SECURE_CONNECTION_HANDLE)
        throw std::runtime_error("Invalid secure connection.");

    X509* cert = SSL_get_peer_certificate(this->m_ssl);
    if (cert == nullptr) return std::nullopt;

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        X509_free(cert);
        throw SecurityException(ERR_get_error());
    }

    if (PEM_write_bio_X509(bio, cert) != 1) {
        BIO_free(bio);
        X509_free(cert);
        throw SecurityException(ERR_get_error());
    }

    const char* str = nullptr;
    std::size_t len = BIO_get_mem_data(bio, &str);
    std::string pem = { str, len };

    BIO_free(bio);
    bio = nullptr;

    X509_free(cert);
    cert = nullptr;

    return Certificate::LoadCertificateFromPEM(pem, std::nullopt);
}

std::int32_t SecureConnection::GetAvailableBytes() const {
    
    if (this->m_ssl == INVALID_SECURE_CONNECTION_HANDLE)
        throw std::runtime_error("Invalid secure connection.");

    SSL_peek(this->m_ssl, nullptr, 0);

    return SSL_pending(this->m_ssl);
}

std::int32_t SecureConnection::Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const {

    if (this->m_ssl == INVALID_SECURE_CONNECTION_HANDLE)
        throw std::runtime_error("Invalid secure connection.");

    if (flags != SocketFlags::NONE)
        throw std::invalid_argument("'flags': This value must be SocketFlags::NONE.");

    if (offset < 0) throw std::out_of_range("'offset' is less than zero.");
    if (offset > data.size()) throw std::out_of_range("'offset' is greater than the buffer size.");
    if (size < 0) throw std::out_of_range("'size' is less than zero.");
    if (size > (data.size() - offset)) throw std::out_of_range("'size' is greater than the buffer size minus 'offset'.");

    const char* const buffer = reinterpret_cast<const char*>(data.data() + offset);

    std::int32_t sent = SSL_write(this->m_ssl, buffer, size);
    if (sent <= 0) throw SecurityException(ERR_get_error());

    return sent;
}

std::int32_t SecureConnection::Send(const std::span<const std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {
    return this->Send(data, offset, size, SocketFlags::NONE);
}

std::int32_t SecureConnection::Send(const std::span<const std::uint8_t> data, const SocketFlags flags) const {
    return this->Send(data, 0, data.size(), flags);
}

std::int32_t SecureConnection::Send(const std::span<const std::uint8_t> data) const {
    return this->Send(data, 0, data.size(), SocketFlags::NONE);
}

std::int32_t SecureConnection::Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size, const SocketFlags flags) const {

    if (this->m_ssl == INVALID_SECURE_CONNECTION_HANDLE)
        throw std::runtime_error("Invalid secure connection.");

    if ((flags != SocketFlags::NONE) && (flags != SocketFlags::PEEK))
        throw std::invalid_argument("'flags': This value must be SocketFlags::NONE or SocketFlags::PEEK.");

    if (offset < 0) throw std::out_of_range("'offset' is less than zero.");
    if (offset > data.size()) throw std::out_of_range("'offset' is greater than the buffer size.");
    if (size < 0) throw std::out_of_range("'size' is less than zero.");
    if (size > (data.size() - offset)) throw std::out_of_range("'size' is greater than the buffer size minus 'offset'.");

    char* const buffer = reinterpret_cast<char*>(data.data() + offset);

    int (*const pfnRead)(SSL*, void*, int) = ( (flags == SocketFlags::NONE) ? &SSL_read : &SSL_peek );

    std::int32_t read = pfnRead(this->m_ssl, buffer, size);
    if (read <= 0) throw SecurityException(ERR_get_error());

    return read;
}

std::int32_t SecureConnection::Receive(const std::span<std::uint8_t> data, const std::int32_t offset, const std::int32_t size) const {
    return this->Receive(data, offset, size, SocketFlags::NONE);
}

std::int32_t SecureConnection::Receive(const std::span<std::uint8_t> data, const SocketFlags flags) const {
    return this->Receive(data, 0, data.size(), flags);
}

std::int32_t SecureConnection::Receive(const std::span<std::uint8_t> data) const {
    return this->Receive(data, 0, data.size(), SocketFlags::NONE);
}

void SecureConnection::Close() {

    if (this->m_ssl == INVALID_SECURE_CONNECTION_HANDLE)
        throw std::runtime_error("Invalid secure connection.");

    std::int32_t result = SSL_shutdown(this->m_ssl);

    if (result == 0) 
        result = SSL_shutdown(this->m_ssl);

    if (result != 1) {
        SSL_free(this->m_ssl);
        this->m_ssl = INVALID_SECURE_CONNECTION_HANDLE;
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
    return SecureConnection::Connect(ctx, socket.GetNativeSocketHandle(), ConnectFlags::NONE);
}

SecureConnection SecureConnection::Connect(const SecurityContext& ctx, const NativeSocket_t socket) {
    return SecureConnection::Connect(ctx, socket, ConnectFlags::NONE);
}

SecureConnection SecureConnection::Connect(const SecurityContext& ctx, const Socket& socket, const ConnectFlags flags) {
    return SecureConnection::Connect(ctx, socket.GetNativeSocketHandle(), flags);
}

SecureConnection SecureConnection::Connect(const SecurityContext& ctx, const NativeSocket_t socket, const ConnectFlags flags) {

    NativeSecureConnection_t ssl = SecureConnection::CreateConnection(ctx, socket);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        throw SecurityException(ERR_get_error());
    }

    return { ssl };
}

SecureConnection SecureConnection::Accept(const SecurityContext& ctx, const Socket& socket) {
    return SecureConnection::Accept(ctx, socket.GetNativeSocketHandle(), AcceptFlags::NONE);
}

SecureConnection SecureConnection::Accept(const SecurityContext& ctx, const NativeSocket_t socket) {
    return SecureConnection::Accept(ctx, socket, AcceptFlags::NONE);
}

SecureConnection SecureConnection::Accept(const SecurityContext& ctx, const Socket& socket, const AcceptFlags flags) {
    return SecureConnection::Accept(ctx, socket.GetNativeSocketHandle(), flags);
}

SecureConnection SecureConnection::Accept(const SecurityContext& ctx, const NativeSocket_t socket, const AcceptFlags flags) {

    NativeSecureConnection_t ssl = SecureConnection::CreateConnection(ctx, socket);

    std::uint8_t sessionId[32] = { 0 };
    RAND_bytes(sessionId, sizeof(sessionId));

    if (SSL_set_session_id_context(ssl, sessionId, sizeof(sessionId)) != 1) {
        SSL_free(ssl);
        throw SecurityException(ERR_get_error());
    }

    if (static_cast<bool>(flags & AcceptFlags::MUTUAL_AUTHENTICATION)) {

        SSL_set_verify(ssl, (SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT), [] (int, X509_STORE_CTX*) -> int {
            return 1;
        });

    }

    if (SSL_accept(ssl) != 1) {
        SSL_free(ssl);
        throw SecurityException(ERR_get_error());
    }

    return { ssl };
}