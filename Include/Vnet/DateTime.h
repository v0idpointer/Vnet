/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETHTTP_DATETIME_H_
#define _VNETHTTP_DATETIME_H_

#include <Vnet/Exports.h>

#include <string>
#include <string_view>
#include <cstdint>
#include <chrono>
#include <ctime>
#include <tuple>

namespace Vnet {

    class VNETHTTPAPI DateTime {

    private:
        static const std::string_view DAY_NAMES[];
        static const std::string_view MONTH_NAMES[];

    private:
        std::time_t m_time;

    public:
        DateTime(void);
        DateTime(const std::time_t time);
        DateTime(const std::chrono::time_point<std::chrono::system_clock>& timePoint);
        DateTime(const DateTime& dateTime);
        virtual ~DateTime(void);

        DateTime& operator= (const DateTime& dateTime);
        DateTime operator+ (const DateTime& dateTime) const;
        DateTime operator- (const DateTime& dateTime) const;
        DateTime& operator+= (const DateTime& dateTime);
        DateTime& operator-= (const DateTime& dateTime);
        bool operator== (const DateTime& dateTime) const;
        bool operator> (const DateTime& dateTime) const;
        bool operator>= (const DateTime& dateTime) const;
        bool operator< (const DateTime& dateTime) const;
        bool operator<= (const DateTime& dateTime) const;

        template <typename Rep, typename Period>
        inline DateTime operator+ (const std::chrono::duration<Rep, Period>& duration) const {
            return DateTime(this->m_time + static_cast<std::time_t>(duration.count() * Period::num / Period::den));
        }

        template <typename Rep, typename Period>
        inline DateTime operator- (const std::chrono::duration<Rep, Period>& duration) const {
            return DateTime(this->m_time - static_cast<std::time_t>(duration.count() * Period::num / Period::den));
        }

        template <typename Rep, typename Period>
        inline DateTime& operator+= (const std::chrono::duration<Rep, Period>& duration) {
            this->m_time += static_cast<std::time_t>(duration.count() * Period::num / Period::den);
            return static_cast<DateTime&>(*this);
        }

        template <typename Rep, typename Period>
        inline DateTime& operator-= (const std::chrono::duration<Rep, Period>& duration) {
            this->m_time -= static_cast<std::time_t>(duration.count() * Period::num / Period::den);
            return static_cast<DateTime&>(*this);
        }

    private:
        std::tm GetLocalTime(void) const;
        std::tm GetUTCTime(void) const;
        std::tuple<std::int32_t, std::int32_t, std::int32_t> GetTimezoneOffsetEx(void) const;

    public:
        std::time_t GetTime(void) const;
        void SetTime(const std::time_t time);
        void SetTime(const std::chrono::time_point<std::chrono::system_clock>& timePoint);

        std::int32_t GetDate(void) const;
        std::int32_t GetDay(void) const;
        std::int32_t GetFullYear(void) const;
        std::int32_t GetHours(void) const;
        std::int32_t GetMinutes(void) const;
        std::int32_t GetMonth(void) const;
        std::int32_t GetSeconds(void) const;
        std::int32_t GetTimezoneOffset(void) const;

        std::int32_t GetUTCDate(void) const;
        std::int32_t GetUTCDay(void) const;
        std::int32_t GetUTCFullYear(void) const;
        std::int32_t GetUTCHours(void) const;
        std::int32_t GetUTCMinutes(void) const;
        std::int32_t GetUTCMonth(void) const;
        std::int32_t GetUTCSeconds(void) const;
        
        std::string ToString(void) const;
        std::string ToUTCString(void) const;
        std::string ToISO8601String(void) const;

        static DateTime Now(void);
        static DateTime MinDate(void);
        static DateTime MaxDate(void);

    };

}

#endif // _VNETHTTP_DATETIME_H_