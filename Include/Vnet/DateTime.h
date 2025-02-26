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

        /**
         * Constructs a new DateTime object set to January 1, 1970.
         */
        DateTime(void);

        /**
         * Constructs a new DateTime object.
         * 
         * @param time A Unix timestamp.
         */
        DateTime(const std::time_t time);

        /**
         * Constructs a new DateTime object.
         * 
         * @param timePoint A Unix timestamp.
         */
        DateTime(const std::chrono::time_point<std::chrono::system_clock>& timePoint);

        /**
         * Constructs a new DateTime object by copying an existing one.
         * 
         * @param dateTime A DateTime object to copy.
         */
        DateTime(const DateTime& dateTime);

        virtual ~DateTime(void);

        /**
         * Assigns the value from an existing DateTime object to this object.
         * 
         * @param dateTime A DateTime object to copy.
         */
        DateTime& operator= (const DateTime& dateTime);

        /**
         * Adds the specified date and time to this DateTime object.
         * 
         * @param dateTime The date and time to add, represented as a DateTime object.
         * @returns A new DateTime object.
         */
        DateTime operator+ (const DateTime& dateTime) const;

        /**
         * Subtracts the specified date and time from this DateTime object.
         * 
         * @param dateTime The date and time to subtract, represented as a DateTime object.
         * @returns A new DateTime object.
         */
        DateTime operator- (const DateTime& dateTime) const;

        /**
         * Adds the specified date and time to this DateTime object.
         * 
         * @param dateTime The date and time to add, represented as a DateTime object.
         * @returns A reference to this DateTime object after addition.
         */
        DateTime& operator+= (const DateTime& dateTime);

        /**
         * Subtracts the specified date and time from this DateTime object.
         * 
         * @param dateTime The date and time to subtract, represented as a DateTime object.
         * @returns A reference to this DateTime object after subtraction.
         */
        DateTime& operator-= (const DateTime& dateTime);
        
        /**
         * Compares this DateTime object with another for equality.
         * 
         * @param dateTime A DateTime object to compare with.
         * @returns true if the DateTime objects are equal; otherwise, false.
         */
        bool operator== (const DateTime& dateTime) const;

        /**
         * Compares this DateTime object with another to determine if it is greater.
         * 
         * This operator checks if this DateTime object represents a point in time
         * that is later than the point in time represented by the provided DateTime object.
         * 
         * @param dateTime A DateTime object to compare with.
         * @returns true if this DateTime object is greater than the provided
         * DateTime object; otherwise, false.
         */
        bool operator> (const DateTime& dateTime) const;

        /**
         * Compares this DateTime object with another to determine if it is greater or equal.
         * 
         * This operator checks if this DateTime object represents a point in time
         * that is later than or equal to the point in time represented by the provided DateTime object.
         * 
         * @param dateTime A DateTime object to compare with.
         * @returns true if this DateTime object is greater than or equal to
         * the provided DateTime object; otherwise, false.
         */
        bool operator>= (const DateTime& dateTime) const;

        /**
         * Compares this DateTime object with another to determine if it is lesser.
         * 
         * This operator checks if this DateTime object represents a point in time
         * that is earlier than the point in time represented by the provided DateTime object.
         * 
         * @param dateTime A DateTime object to compare with.
         * @returns true if this DateTime object is lesser than the provided
         * DateTime object; otherwise, false.
         */
        bool operator< (const DateTime& dateTime) const;

        /**
         * Compares this DateTime object with another to determine if it is lesser or equal.
         * 
         * This operator checks if this DateTime object represents a point in time
         * that is earlier than or equal to the point in time represented by the provided DateTime object.
         * 
         * @param dateTime A DateTime object to compare with.
         * @returns true if this DateTime object is lesser than or equal to
         * the provided DateTime object; otherwise, false.
         */
        bool operator<= (const DateTime& dateTime) const;

        /**
         * Adds the specified time interval to this DateTime object.
         * 
         * @tparam Rep Represents the number of ticks.
         * @tparam Period An std::ratio representing the tick period.
         * @param duration The time interval to add, represented as an std::chrono::duration object.
         * @returns A new DateTime object.
         */
        template <typename Rep, typename Period>
        inline DateTime operator+ (const std::chrono::duration<Rep, Period>& duration) const {
            return DateTime(this->m_time + static_cast<std::time_t>(duration.count() * Period::num / Period::den));
        }

        /**
         * Subtracts the specified time interval from this DateTime object.
         * 
         * @tparam Rep Represents the number of ticks.
         * @tparam Period An std::ratio representing the tick period.
         * @param duration The time interval to subtract, represented as an std::chrono::duration object.
         * @returns A new DateTime object.
         */
        template <typename Rep, typename Period>
        inline DateTime operator- (const std::chrono::duration<Rep, Period>& duration) const {
            return DateTime(this->m_time - static_cast<std::time_t>(duration.count() * Period::num / Period::den));
        }

        /**
         * Adds the specified time interval to this DateTime object.
         * 
         * @tparam Represents the number of ticks.
         * @tparam Period An std::ratio representing the tick period.
         * @param duration The time interval to add, represented as an std::chrono::duration object.
         * @returns A reference to this DateTime object after addition.
         */
        template <typename Rep, typename Period>
        inline DateTime& operator+= (const std::chrono::duration<Rep, Period>& duration) {
            this->m_time += static_cast<std::time_t>(duration.count() * Period::num / Period::den);
            return static_cast<DateTime&>(*this);
        }

        /**
         * Subtracts the specified time interval from this DateTime object.
         * 
         * @tparam Rep Represents the number of ticks.
         * @tparam Period An std::ratio representing the tick period.
         * @param duration The time interval to subtract, represented as an std::chrono::duration object.
         * @returns A reference to this DateTime object after subtraction.
         */
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
         * 
         * @returns A time_t.
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
         * 
         * @returns A string.
         */
        std::string ToString(void) const;

        /**
         * Returns the string representation of the DateTime object in the format specified by RFC 7231.
         * 
         * @returns A string.
         */
        std::string ToUTCString(void) const;

        /**
         * Returns the string representation of the DateTime object in the ISO 8601 format.
         * 
         * @returns A string.
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