/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETWEB_WEB_ILOGGER_H_
#define _VNETWEB_WEB_ILOGGER_H_

#include <Vnet/Exports.h>

#include <string>
#include <cstdint>

namespace Vnet::Web {

    enum class VNETWEBAPI SeverityLevel : std::uint8_t {

        TRACE,
        DEBUG,
        INFO,
        WARN,
        ERR,
        FATAL,

    };

    class VNETWEBAPI ILogger {
    public:
        inline virtual ~ILogger(void) { }
        virtual void Log(const SeverityLevel severity, const std::string& message) = 0;
    };

}

#endif // _VNETWEB_WEB_ILOGGER_H_