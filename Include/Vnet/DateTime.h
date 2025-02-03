/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_DATETIME_H_
#define _VNETHTTP_DATETIME_H_

#include <Vnet/Exports.h>

#include <string>
#include <string_view>
#include <cstdint>
#include <chrono>
#include <ctime>
#include <utility>
#include <optional>

namespace Vnet {

    /**
     * Represents a moment in time, expressed as date and time.
     */
    class VNETHTTPAPI DateTime {

    private:
        static const std::string_view DAY_NAMES[];
        static const std::string_view MONTH_NAMES[];

    public:

        /**
         * Thursday, January 1, 1970 00:00:00
         */
        static const DateTime MIN_DATE;

        /**
         * Tuesday, January 19, 2038 03:14:07
         */
        static const DateTime MAX_DATE;

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
        std::pair<std::int32_t, std::int32_t> GetTimezoneOffsetEx(void) const;

    public:

        /**
         * Returns the number of seconds since the Unix epoch (January 1, 1970).
         */
        std::time_t GetTime(void) const;

        /**
         * Sets the time.
         * 
         * @param time A Unix timestamp.
         */
        void SetTime(const std::time_t time);

        /**
         * Sets the time.
         * 
         * @param timePoint A Unix timestamp.
         */
        void SetTime(const std::chrono::time_point<std::chrono::system_clock>& timePoint);

        /**
         * Returns the day of the month according to local time.
         * 
         * @returns An integer, between 1 and 31.
         */
        std::int32_t GetDate(void) const;

        /**
         * Returns the day of the week according to local time.
         * 
         * @returns An integer, between 0 and 6.
         */
        std::int32_t GetDay(void) const;

        /**
         * Returns the year according to local time.
         * 
         * @returns An integer.
         */
        std::int32_t GetFullYear(void) const;

        /**
         * Returns the hours according to local time.
         * 
         * @returns An integer, between 0 and 23.
         */
        std::int32_t GetHours(void) const;

        /**
         * Returns the minutes according to local time.
         * 
         * @returns An integer, between 0 and 59.
         */
        std::int32_t GetMinutes(void) const;

        /**
         * Returns the month according to local time.
         * 
         * @returns An integer, between 0 and 11.
         */
        std::int32_t GetMonth(void) const;

        /**
         * Returns the seconds according to local time.
         * 
         * @returns An integer, between 0 and 59.
         */
        std::int32_t GetSeconds(void) const;

        /**
         * Returns the timezone difference between local time and Coordinated Universal Time (UTC).
         * 
         * @returns An integer representing the timezone difference in seconds.
         */
        std::int32_t GetTimezoneOffset(void) const;

        /**
         * Returns the day of the month according to Coordinated Universal Time (UTC). 
         * 
         * @returns An integer, between 1 and 31.
         */
        std::int32_t GetUTCDate(void) const;

        /**
         * Returns the day of the week according to Coordinated Universal Time (UTC).
         * 
         * @returns An integer, between 0 and 6.
         */
        std::int32_t GetUTCDay(void) const;

        /**
         * Returns the year according to Coordinated Universal Time (UTC).
         * 
         * @returns An integer.
         */
        std::int32_t GetUTCFullYear(void) const;

        /**
         * Returns the hours according to Coordinated Universal Time (UTC).
         * 
         * @returns An integer, between 0 and 23.
         */
        std::int32_t GetUTCHours(void) const;

        /**
         * Returns the minutes according to Coordinated Universal Time (UTC).
         * 
         * @returns An integer, between 0 and 59.
         */
        std::int32_t GetUTCMinutes(void) const;

        /**
         * Returns the month according to Coordinated Universal Time (UTC).
         * 
         * @returns An integer, between 0 and 11.
         */
        std::int32_t GetUTCMonth(void) const;

        /**
         * Returns the seconds according to Coordinated Universal Time (UTC).
         * 
         * @returns An integer, between 0 and 59.
         */
        std::int32_t GetUTCSeconds(void) const;
        
        /**
         * Returns the string representation of the DateTime object in the current timezone.
         */
        std::string ToString(void) const;

        /**
         * Returns the string representation of the DateTime object in the format specified by RFC 7231.
         */
        std::string ToUTCString(void) const;

        /**
         * Returns the string representation of the DateTime object in the ISO 8601 format.
         */
        std::string ToISO8601String(void) const;

        /**
         * Retrieves the current date and time.
         * 
         * @returns A DateTime object set to the current date and time.
         */
        static DateTime Now(void);

    private:
        static std::optional<DateTime> ParseDateFromString(std::string_view str, const bool exceptions);
        static std::optional<DateTime> ParseDateFromUTCString(std::string_view str, const bool exceptions);
        static std::optional<DateTime> ParseDateFromISO8601String(const std::string_view str, const bool exceptions);

    public:

        /**
         * Parses a string representation of a DateTime object.
         * 
         * @param str A string representation of a DateTime object.
         * @returns A DateTime object.
         * @exception std::runtime_error - Bad datetime format.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         */
        static DateTime Parse(const std::string_view str);

        /**
         * Parses a string representation of a DateTime object in the date format specified by RFC 7231.
         * 
         * @param str A string representation of a DateTime object.
         * @returns A DateTime object.
         * @exception std::runtime_error - Bad datetime format.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         */
        static DateTime ParseUTCDate(const std::string_view str);

        /**
         * Parses a string representation of a DateTime object in the ISO 8601 format.
         * 
         * @param str A string representation of a DateTime object.
         * @returns A DateTime object.
         * @exception std::runtime_error - Bad datetime format.
         * @exception std::invalid_argument - The 'str' parameter is an empty string.
         */
        static DateTime ParseISO8601Date(const std::string_view str);

        /**
         * Tries to parse a string representation of a DateTime object.
         * 
         * @param str A string representation of a DateTime object.
         * @returns If successful, a DateTime object is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<DateTime> TryParse(const std::string_view str);

        /**
         * Tries to parse a string representation of a DateTime object in the date format specified by RFC 7231.
         * 
         * @param str A string representation of a DateTime object.
         * @returns If successful, a DateTime object is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<DateTime> TryParseUTCDate(const std::string_view str);

        /**
         * Tries to parse a string representation of a DateTime object in the ISO 8601 format.
         * 
         * @param str A string representation of a DateTime object.
         * @returns If successful, a DateTime object is returned; otherwise, std::nullopt is returned.
         */
        static std::optional<DateTime> TryParseISO8601Date(const std::string_view str);

    };

}

#endif // _VNETHTTP_DATETIME_H_