/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/DateTime.h>
#include <Vnet/Web/WebServer.h>
#include <Vnet/Sockets/IpSocketAddress.h>
#include <Vnet/Sockets/SocketException.h>
#include <Vnet/Security/SecurityException.h>
#include <Vnet/Http/HttpException.h>

#ifdef VNET_PLATFORM_WINDOWS
    #include <WinSock2.h>
    constexpr std::int32_t SOCKET_ERROR_AGAIN = WSAEWOULDBLOCK;
    constexpr std::int32_t SOCKET_ERROR_WOULD_BLOCK = WSAEWOULDBLOCK;
#else
    #include <errno.h>
    constexpr std::int32_t SOCKET_ERROR_AGAIN = EAGAIN;
    constexpr std::int32_t SOCKET_ERROR_WOULD_BLOCK = EWOULDBLOCK;
#endif

#include <cstring>

using namespace Vnet;
using namespace Vnet::Web;
using namespace Vnet::Net;
using namespace Vnet::Http;
using namespace Vnet::Sockets;
using namespace Vnet::Security;

WebServer::WebServer(std::shared_ptr<ILogger> logger, const std::int32_t threadCount) {

    if (threadCount <= 0)
        throw std::invalid_argument("'threadCount': Cannot create a thread pool of zero or fewer threads.");

    this->m_logger = std::move(logger);
    this->m_threadPool = std::make_unique<decltype(WebServer::m_threadPool)::element_type>(threadCount);

    this->m_managerIdle = true;
    this->m_listenerIdle = true;

    this->m_running = true;
    this->m_managing = true;
    this->m_managerThread = std::thread(&WebServer::ManagerThreadProc, this);

}

WebServer::~WebServer() {

    this->CloseConnections();

    this->m_running = false;

    if (this->m_listenerThread.has_value()) {
        this->m_listenerThread->join();
        this->m_socket->Close();
    }

    this->m_managerThread.join();

}

void WebServer::Log(const SeverityLevel severity, const std::string& message) const {
    if (this->m_logger) this->m_logger->Log(severity, message);
}

void WebServer::Bind(const std::optional<IpAddress>& ipAddr, const Port port) {
    
    const IpSocketAddress sockaddr = { ipAddr.value_or(IpAddress::ANY), port };

    this->m_socket = std::make_unique<Socket>(
        sockaddr.GetAddressFamily(),
        SocketType::STREAM,
        Protocol::TCP
    );

    try { this->m_socket->Bind(sockaddr); }
    catch (const SocketException& ex) {

        throw SocketException(
            ex.GetErrorCode(),
            std::format("Failed to bind to port. Is there another server running on port {0}?", port)
        );

    }

    this->m_socket->Listen();

    this->m_listening = true;
    this->m_listenerThread = std::thread(&WebServer::ListenerThreadProc, this);

}

bool WebServer::CloseConnections() {
    
    std::unique_lock<std::mutex> lock = { this->m_mutex, std::defer_lock };

    bool listening = this->m_listening;

    lock.lock();
    this->m_listening = false;
    this->m_managing = false;
    lock.unlock();

    // wait!!!
    while (true) {
        if (this->m_listenerIdle && this->m_managerIdle && (this->m_threadPool->GetActiveThreadCount() == 0)) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    lock.lock();
    
    // close the connections:
    while (!this->m_connections.empty()) {

        std::unique_ptr<HttpStream> stream = std::move(this->m_connections.front());
        this->m_connections.pop();

        try { stream->Close(); }
        catch (std::exception& ex) {
            this->Err("CloseConnections: HttpStream::Close failed: {0}", ex.what());
        }

    }

    this->m_managing = true;
    lock.unlock();

    return listening;
}

void WebServer::ListenerThreadProc() {
    while (this->m_running) {

        std::unique_lock<std::mutex> lock = { this->m_mutex, std::defer_lock };

        if (!this->m_listening) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            this->m_listenerIdle = true;
            continue;
        }

        this->m_listenerIdle = false;

        if (!this->m_socket->Poll(PollEvent::READ, 10))
            continue;

        std::optional<Socket> socket;
        std::optional<SecureConnection> ssl;

        try { socket = this->m_socket->Accept(); }
        catch (const SocketException& ex) {
            this->Err("ListenerThreadProc: Socket::Accept failed: {0} (error code: 0x{1:08X})", ex.what(), ex.GetErrorCode());
            continue;
        }

        lock.lock();

        if (this->m_ctx) {

            try { ssl = SecureConnection::Accept(*this->m_ctx, *this->m_socket, AcceptFlags::NONE); }
            catch (const SecurityException& ex) {
                this->Err("ListenerThreadProc: SecureConnection::Accept failed: {0} (error code: 0x{1:08X})", ex.what(), ex.GetErrorCode());
                lock.unlock();
                continue;
            }

        }

        std::unique_ptr<HttpStream> stream = std::make_unique<HttpStream>(
            std::make_shared<Socket>(std::move(*socket)),
            (ssl.has_value() ? std::make_shared<SecureConnection>(std::move(*ssl)) : nullptr)
        );

        this->m_connections.push(std::move(stream));
        this->Info("ListenerThreadProc: connection accepted.");

        lock.unlock();

    }
}

void WebServer::ManagerThreadProc() { 
    while (this->m_running) {
        
        std::unique_lock<std::mutex> lock = { this->m_mutex, std::defer_lock };

        if (!this->m_managing) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            this->m_managerIdle = true;
            continue;
        }

        this->m_managerIdle = false;

        lock.lock();
        if (this->m_connections.empty()) {
            lock.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

        std::unique_ptr<HttpStream> stream = std::move(this->m_connections.front());
        this->m_connections.pop();
        lock.unlock();

        if (!WebServer::IsConnected(*stream->GetSocket())) {
            this->Info("Socket disconnected. Connection dropped.");
            continue;
        }

        if (WebServer::HasAvailableData(*stream)) {
            this->m_threadPool->EnqueueJob(&WebServer::ConnectionHandlerProc, this, std::move(stream), std::nullopt);
            this->Info("Connection enqueued.");
            continue;
        }

        lock.lock();
        this->m_connections.push(std::move(stream));
        lock.unlock();

    }
}

void WebServer::ConnectionHandlerProc(std::unique_ptr<HttpStream> stream, std::optional<HttpRequest> request) { 
    
    std::unique_lock<std::mutex> lock = { this->m_mutex, std::defer_lock };

    std::optional<HttpRequest> req;
    HttpResponse res;

    bool keepAlive = true;

    // read the request:
    if (request.has_value()) req = std::move(request.value());
    else {

        try { stream->Receive(req.emplace()); }
        catch (const HttpException& ex) {
            this->Err("Receive: {0}", ex.what());
            res.SetStatusCode(ex.GetStatusCode().value_or(HttpStatusCode::BAD_REQUEST));
            req = std::nullopt;
        }
        catch (const std::exception& ex) {
            this->Err("Receive: {0}", ex.what());
            return;
        }

    }

    // handle the request:
    if (req.has_value()) {
        WebServer::CreateDummyResponse(res); // TODO: remove this when routers get implemented.
    }

    // set the default server headers:
    res.GetHeaders().Set("Connection", (keepAlive ? "keep-alive" : "close"));
    res.GetHeaders().Set("Date", DateTime::Now().ToUTCString());
    res.GetHeaders().Set("Server", "Vnet WebServer");

    // send the response:
    try { stream->Send(res); }
    catch (const std::exception& ex) {
        this->Err("Send: {0}", ex.what());
        return;
    }

    if (!keepAlive) {

        try { stream->Close(); }
        catch (const SocketException& ex) {
            this->Err("Close: {0}", ex.what());
            return;
        }

    }

    // add the connection back in the connections queue:
    lock.lock();
    this->m_connections.push(std::move(stream));
    lock.unlock();

}

bool WebServer::IsConnected(Socket& socket) {

    if (socket.GetNativeSocketHandle() == INVALID_SOCKET_HANDLE)
        return false;

    try { socket.SetBlocking(false); }
    catch (const SocketException&) {
        return false;
    }

    std::int32_t read = 0;
    std::uint8_t dummy[1] = { 0 };

    try { read = socket.Receive(dummy, 0, 1, SocketFlags::PEEK); }
    catch (const SocketException& ex) {

        try { socket.SetBlocking(true); }
        catch (const SocketException&) {
            return false;
        }

        if ((ex.GetErrorCode() == SOCKET_ERROR_AGAIN) || (ex.GetErrorCode() == SOCKET_ERROR_WOULD_BLOCK))
            return true;

        return false;
    }

    try { socket.SetBlocking(true); }
    catch (const SocketException&) {
        return false;
    }

    return (read > 0);
}

bool WebServer::HasAvailableData(HttpStream& stream) {

    std::int32_t available = 0;
    try { available = stream.GetAvailableBytes(); }
    catch (const std::exception&) {
        return false;
    }

    return (available > 0);
}

void WebServer::CreateDummyResponse(HttpResponse& res) {

    res.SetStatusCode(HttpStatusCode::OK);
    res.GetHeaders().Add("Content-Type", "text/html");
    res.ResizePayload(21);
    
    std::memcpy(res.GetPayload().data(), "<h3>Hello World!</h3>", 21);

}

bool WebServer::AddConnection(std::unique_ptr<HttpStream>&& connection) noexcept {

    const std::lock_guard<std::mutex> guard(this->m_mutex);

    if (connection == nullptr) 
        return false;

    if (connection->GetSocket()->GetNativeSocketHandle() == INVALID_SOCKET_HANDLE) 
        return false;

    if (connection->GetSecureConnection() && (connection->GetSecureConnection()->GetNativeSecureConnectionHandle() == INVALID_SECURE_CONNECTION_HANDLE))
        return false;

    this->m_connections.push(std::move(connection));

    return true;
}

bool WebServer::AddConnection(std::unique_ptr<HttpStream>&& connection, HttpRequest&& request) noexcept {

    const std::lock_guard<std::mutex> guard(this->m_mutex);

    if (connection == nullptr) 
        return false;

    if (connection->GetSocket()->GetNativeSocketHandle() == INVALID_SOCKET_HANDLE) 
        return false;

    if (connection->GetSecureConnection() && (connection->GetSecureConnection()->GetNativeSecureConnectionHandle() == INVALID_SECURE_CONNECTION_HANDLE))
        return false;

    this->m_threadPool->EnqueueJob(&WebServer::ConnectionHandlerProc, this, std::move(connection), std::move(request));

    return true;
}

std::unique_ptr<WebServer> WebServer::Create(
    const std::optional<IpAddress>& ipAddr,
    const std::optional<Port> port,
    const std::optional<std::int32_t> threadCount,
    std::shared_ptr<ILogger> logger
) {

    std::int32_t hardwareConcurency = std::thread::hardware_concurrency();
    if (hardwareConcurency <= 0) hardwareConcurency = 1;
    
    std::unique_ptr<WebServer> server = std::unique_ptr<WebServer>(new WebServer(
        std::move(logger),
        threadCount.value_or(hardwareConcurency)
    ));

    if (port.has_value()) server->Bind(ipAddr, port.value());
    
    return std::move(server);
}