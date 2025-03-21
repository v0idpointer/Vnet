/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#include <Vnet/DateTime.h>
#include <Vnet/Web/WebServer.h>
#include <Vnet/Sockets/IpSocketAddress.h>
#include <Vnet/Sockets/SocketException.h>
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

#include <iostream>
#include <cstring>

using namespace Vnet;
using namespace Vnet::Web;
using namespace Vnet::Net;
using namespace Vnet::Http;
using namespace Vnet::Sockets;
using namespace Vnet::Security;

WebServer::WebServer(const std::int32_t threadCount) {

    if (threadCount <= 0)
        throw std::invalid_argument("'threadCount': Cannot create a thread pool of zero or fewer threads.");

    this->m_threadPool = std::make_unique<decltype(WebServer::m_threadPool)::element_type>(threadCount);

    this->m_running = true;
    this->m_managing = true;
    this->m_managerThread = std::thread(&WebServer::ManagerThreadProc, this);

}

WebServer::~WebServer() {
    
    this->m_running = false;
    this->m_managerThread.join();

}

void WebServer::Bind(const std::optional<IpAddress>& ipAddr, const Port port) {
    // TODO: implement.
}

void WebServer::ListenerThreadProc() {
    // TODO: implement.
}

void WebServer::ManagerThreadProc() { 
    while (this->m_running) {
        
        std::unique_lock<std::mutex> lock = { this->m_mutex, std::defer_lock };

        if (!this->m_managing) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }

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
            std::cout << "Socket disconnected. Connection dropped." << std::endl;
            continue;
        }

        if (WebServer::HasAvailableData(*stream)) {
            this->m_threadPool->EnqueueJob(&WebServer::ConnectionHandlerProc, this, std::move(stream), std::nullopt);
            std::cout << "Connection enqueued." << std::endl;
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

    bool keepAlive = false;

    // read the request:
    if (request.has_value()) req = std::move(request.value());
    else {

        try { stream->Receive(req.emplace()); }
        catch (const HttpException& ex) {
            std::cout << "Receive: " << ex.what() << std::endl;
            res.SetStatusCode(ex.GetStatusCode().value_or(HttpStatusCode::BAD_REQUEST));
            req = std::nullopt;
        }
        catch (const std::exception& ex) {
            std::cout << "Receive: " << ex.what() << std::endl;
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
        std::cout << "Send: " << ex.what() << std::endl;
        return;
    }

    if (!keepAlive) {

        try { stream->Close(); }
        catch (const SocketException& ex) {
            std::cout << "Close: " << ex.what() << std::endl;
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
    const std::optional<std::int32_t> threadCount
) {

    std::int32_t hardwareConcurency = std::thread::hardware_concurrency();
    if (hardwareConcurency <= 0) hardwareConcurency = 1;
    
    std::unique_ptr<WebServer> server = std::unique_ptr<WebServer>(new WebServer(
        threadCount.value_or(hardwareConcurency)
    ));

    if (port.has_value()) server->Bind(ipAddr, port.value());
    
    return std::move(server);
}