/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETWEB_WEB_WEBSERVER_H_
#define _VNETWEB_WEB_WEBSERVER_H_

#include <Vnet/IpAddress.h>
#include <Vnet/ThreadPool.h>
#include <Vnet/Net/HttpStream.h>
#include <Vnet/Web/ILogger.h>

#include <format>

namespace Vnet::Web {

    /**
     * 
     */
    class VNETWEBAPI WebServer {

    private:
        std::shared_ptr<ILogger> m_logger;

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

        bool m_listening;
        std::optional<std::thread> m_listenerThread;
        std::unique_ptr<Vnet::Sockets::Socket> m_socket;
        std::unique_ptr<Vnet::Security::SecurityContext> m_ctx;

        std::atomic_bool m_managerIdle, m_listenerIdle; // flags to check if a thread has entered it's idle state.

        WebServer(std::shared_ptr<ILogger> logger, const std::int32_t threadCount);

    public:
        WebServer(const WebServer&) = delete;
        WebServer(WebServer&&) noexcept = delete;
        virtual ~WebServer(void);

        WebServer& operator= (const WebServer&) = delete;
        WebServer& operator= (WebServer&&) noexcept = delete;

    private:
        void Log(const SeverityLevel, const std::string&) const;

        template <typename... Args>
        inline void Trace(const std::string& fmt, Args&&... args) const {
            this->Log(SeverityLevel::TRACE, std::vformat(fmt, std::make_format_args(args...)));
        }

        template <typename... Args>
        inline void Debug(const std::string& fmt, Args&&... args) const {
            this->Log(SeverityLevel::DEBUG, std::vformat(fmt, std::make_format_args(args...)));
        }

        template <typename... Args>
        inline void Info(const std::string& fmt, Args&&... args) const {
            this->Log(SeverityLevel::INFO, std::vformat(fmt, std::make_format_args(args...)));
        }

        template <typename... Args>
        inline void Warn(const std::string& fmt, Args&&... args) const {
            this->Log(SeverityLevel::WARN, std::vformat(fmt, std::make_format_args(args...)));
        }

        template <typename... Args>
        inline void Err(const std::string& fmt, Args&&... args) const {
            this->Log(SeverityLevel::ERR, std::vformat(fmt, std::make_format_args(args...)));
        }

        template <typename... Args>
        inline void Fatal(const std::string& fmt, Args&&... args) const {
            this->Log(SeverityLevel::FATAL, std::vformat(fmt, std::make_format_args(args...)));
        }

        void Bind(const std::optional<Vnet::IpAddress>&, const Vnet::Port);
        bool CloseConnections(void);

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
         * @param logger
         * @returns
         * @exception std::invalid_argument - The 'threadCount' parameter is less than or equal to zero.
         * @exception SocketException
         */
        static std::unique_ptr<WebServer> Create(
            const std::optional<Vnet::IpAddress>& ipAddr,
            const std::optional<Vnet::Port> port,
            const std::optional<std::int32_t> threadCount,
            std::shared_ptr<ILogger> logger
        );

    };

}

#endif // _VNETWEB_WEB_WEBSERVER_H_