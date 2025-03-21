/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETWEB_WEB_WEBSERVER_H_
#define _VNETWEB_WEB_WEBSERVER_H_

#include <Vnet/IpAddress.h>
#include <Vnet/ThreadPool.h>
#include <Vnet/Net/HttpStream.h>

namespace Vnet::Web {

    /**
     * 
     */
    class VNETWEBAPI WebServer {

    private:
        bool m_running;
        bool m_managing;
        std::mutex m_mutex;
        std::thread m_managerThread;
        std::queue<std::unique_ptr<Vnet::Net::HttpStream>> m_connections;
        std::unique_ptr<Vnet::ThreadPool<
            WebServer*,
            std::unique_ptr<Vnet::Net::HttpStream>,
            std::optional<Vnet::Http::HttpRequest>
        >> m_threadPool;

        // bool m_listening;
        // std::optional<std::thread> m_listenerThread;
        // std::unique_ptr<Vnet::Sockets::Socket> m_socket;
        // std::unique_ptr<Vnet::Security::SecurityContext> m_ctx;

        WebServer(const std::int32_t threadCount);

    public:
        WebServer(const WebServer&) = delete;
        WebServer(WebServer&&) noexcept = delete;
        virtual ~WebServer(void);

        WebServer& operator= (const WebServer&) = delete;
        WebServer& operator= (WebServer&&) noexcept = delete;

    private:
        void Bind(const std::optional<Vnet::IpAddress>&, const Vnet::Port);

        void ListenerThreadProc(void);
        void ManagerThreadProc(void);
        void ConnectionHandlerProc(std::unique_ptr<Vnet::Net::HttpStream>, std::optional<Vnet::Http::HttpRequest>);

        static bool IsConnected(Vnet::Sockets::Socket&);
        static bool HasAvailableData(Vnet::Net::HttpStream&);
        static void CreateDummyResponse(Vnet::Http::HttpResponse&);

    public:
        bool AddConnection(std::unique_ptr<Vnet::Net::HttpStream>&& connection) noexcept;
        bool AddConnection(std::unique_ptr<Vnet::Net::HttpStream>&& connection, Vnet::Http::HttpRequest&& request) noexcept;

        /**
         * 
         * 
         * @param ipAddr
         * @param port
         * @param threadCount
         * @returns
         * @exception std::invalid_argument - The 'threadCount' parameter is less than or equal to zero.
         */
        static std::unique_ptr<WebServer> Create(
            const std::optional<Vnet::IpAddress>& ipAddr,
            const std::optional<Vnet::Port> port,
            const std::optional<std::int32_t> threadCount
        );

    };

}

#endif // _VNETWEB_WEB_WEBSERVER_H_