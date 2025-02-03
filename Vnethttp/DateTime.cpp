/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef VNET_BUILD_VNETHTTP
#define VNET_BUILD_VNETHTTP
#endif

#include <Vnet/DateTime.h>

#include <cstring>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <algorithm>
#include <exception>
#include <stdexcept>

using namespace Vnet;

const std::string_view DateTime::DAY_NAMES[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", };
const std::string_view DateTime::MONTH_NAMES[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", };
const DateTime DateTime::MIN_DATE = { 0 };
const DateTime DateTime::MAX_DATE = { 2147483647 };

DateTime::DateTime() : DateTime(0) { }

DateTime::DateTime(const std::time_t time) : m_time(time) { }

DateTime::DateTime(const std::chrono::time_point<std::chrono::system_clock>& timePoint)
    : DateTime(std::chrono::system_clock::to_time_t(timePoint)) { }

DateTime::DateTime(const DateTime& dateTime) {
    this->operator= (dateTime);
}

DateTime::~DateTime() { }

DateTime& DateTime::operator= (const DateTime& dateTime) {
    if (this != &dateTime) this->m_time = dateTime.m_time;
    return static_cast<DateTime&>(*this);
}

DateTime DateTime::operator+ (const DateTime& dateTime) const {
    return DateTime(this->m_time + dateTime.m_time);
}

DateTime DateTime::operator- (const DateTime& dateTime) const {
    return DateTime(this->m_time - dateTime.m_time);
}

DateTime& DateTime::operator+= (const DateTime& dateTime) {
    this->m_time += dateTime.m_time;
    return static_cast<DateTime&>(*this);
}

DateTime& DateTime::operator-= (const DateTime& dateTime) {
    this->m_time -= dateTime.m_time;
    return static_cast<DateTime&>(*this);
}

bool DateTime::operator== (const DateTime& dateTime) const {
    return (this->m_time == dateTime.m_time);
}

bool DateTime::operator> (const DateTime& dateTime) const {
    return (this->m_time > dateTime.m_time);
}

bool DateTime::operator>= (const DateTime& dateTime) const {
    return (this->m_time >= dateTime.m_time);
}

bool DateTime::operator< (const DateTime& dateTime) const {
    return (this->m_time < dateTime.m_time);
}

bool DateTime::operator<= (const DateTime& dateTime) const {
    return (this->m_time <= dateTime.m_time);
}

std::tm DateTime::GetLocalTime() const {

    std::tm localTm = { 0 };
    std::tm* pTm = nullptr;

    if ((pTm = localtime(&this->m_time)) != nullptr)
        std::memcpy(&localTm, pTm, sizeof(std::tm));

    return localTm;
}

std::tm DateTime::GetUTCTime() const {

    std::tm localTm = { 0 };
    std::tm* pTm = nullptr;

    if ((pTm = gmtime(&this->m_time)) != nullptr)
        std::memcpy(&localTm, pTm, sizeof(std::tm));

    return localTm;
}

std::pair<std::int32_t, std::int32_t> DateTime::GetTimezoneOffsetEx() const {
    
#if defined(__cpp_lib_format) && (__cpp_lib_format >= 201907L)

    const std::chrono::zoned_time zt = { std::chrono::current_zone(), std::chrono::system_clock::from_time_t(this->m_time) };
    const std::chrono::sys_info info = zt.get_info();
    const std::int32_t hourOffset = std::chrono::duration_cast<std::chrono::hours>(info.offset).count();
	const std::int32_t minuteOffset = std::chrono::duration_cast<std::chrono::minutes>(info.offset % std::chrono::hours(1)).count();

#else
    
    std::int32_t (*getOffsetMinutes)(std::tm*, std::tm*) = [] (std::tm* localTm, std::tm* utcTm) {
        const std::time_t localTime = std::mktime(localTm);
        const std::time_t utcTime = std::mktime(utcTm);
        return static_cast<std::int32_t>(std::difftime(localTime, utcTime) / 60);
    };

    std::tm localTm = this->GetLocalTime();
    std::tm utcTm = this->GetUTCTime();

    const std::int32_t offset = getOffsetMinutes(&localTm, &utcTm);
    const std::int32_t hourOffset = (offset / 60);
    const std::int32_t minuteOffset = (offset % 60);

#endif

    return { hourOffset, minuteOffset };
}

std::time_t DateTime::GetTime() const {
    return this->m_time;
}

void DateTime::SetTime(const std::time_t time) {
    this->m_time = time;
}

void DateTime::SetTime(const std::chrono::time_point<std::chrono::system_clock>& timePoint) {
    this->SetTime(std::chrono::system_clock::to_time_t(timePoint));
}

std::int32_t DateTime::GetDate(void) const {
    return this->GetLocalTime().tm_mday;
}

std::int32_t DateTime::GetDay(void) const {
    return this->GetLocalTime().tm_wday;
}

std::int32_t DateTime::GetFullYear(void) const {
    return (this->GetLocalTime().tm_year + 1900);
}

std::int32_t DateTime::GetHours(void) const {
    return this->GetLocalTime().tm_hour;
}

std::int32_t DateTime::GetMinutes(void) const {
    return this->GetLocalTime().tm_min;
}

std::int32_t DateTime::GetMonth(void) const {
    return this->GetLocalTime().tm_mon;
}

std::int32_t DateTime::GetSeconds(void) const {
    return this->GetLocalTime().tm_sec;
}

std::int32_t DateTime::GetTimezoneOffset(void) const {
    
    const auto [hourOffset, minuteOffset] = this->GetTimezoneOffsetEx();

    std::int32_t offset = 0;
    offset += std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours(hourOffset)).count();
    offset += std::chrono::duration_cast<std::chrono::seconds>(std::chrono::minutes(minuteOffset)).count();

    return offset;
}

std::int32_t DateTime::GetUTCDate(void) const {
    return this->GetUTCTime().tm_mday;
}

std::int32_t DateTime::GetUTCDay(void) const {
    return this->GetUTCTime().tm_wday;
}

std::int32_t DateTime::GetUTCFullYear(void) const {
    return (this->GetUTCTime().tm_year + 1900);
}

std::int32_t DateTime::GetUTCHours(void) const {
    return this->GetUTCTime().tm_hour;
}

std::int32_t DateTime::GetUTCMinutes(void) const {
    return this->GetUTCTime().tm_min;
}

std::int32_t DateTime::GetUTCMonth(void) const {
    return this->GetUTCTime().tm_mon;
}

std::int32_t DateTime::GetUTCSeconds(void) const {
    return this->GetUTCTime().tm_sec;
}

std::string DateTime::ToString() const {
    
    std::ostringstream stream;
    const std::tm tm = this->GetLocalTime();
    const auto [hourOffset, minuteOffset] = this->GetTimezoneOffsetEx();

    stream << DateTime::DAY_NAMES[tm.tm_wday] << " ";
    stream << DateTime::MONTH_NAMES[tm.tm_mon] << " ";
    stream << std::setw(2) << std::setfill('0') << tm.tm_mday << " ";
    stream << (tm.tm_year + 1900) << " ";
    stream << std::setw(2) << std::setfill('0') << tm.tm_hour << ":";
    stream << std::setw(2) << std::setfill('0') << tm.tm_min << ":";
    stream << std::setw(2) << std::setfill('0') << tm.tm_sec << " ";
    stream << "GMT" << ((hourOffset < 0) ? '-' : '+') << std::setw(2) << std::setfill('0') << std::abs(hourOffset);
    stream << std::setw(2) << std::setfill('0') << minuteOffset;

    return stream.str();
}

std::string DateTime::ToUTCString() const {
    
    std::ostringstream stream;
    const std::tm tm = this->GetUTCTime();

    stream << DateTime::DAY_NAMES[tm.tm_wday] << ", ";
    stream << std::setw(2) << std::setfill('0') << tm.tm_mday << " ";
    stream << DateTime::MONTH_NAMES[tm.tm_mon] << " ";
    stream << (tm.tm_year + 1900) << " ";
    stream << std::setw(2) << std::setfill('0') << tm.tm_hour << ":";
    stream << std::setw(2) << std::setfill('0') << tm.tm_min << ":";
    stream << std::setw(2) << std::setfill('0') << tm.tm_sec << " GMT";

    return stream.str();
}

std::string DateTime::ToISO8601String() const {
    
    std::ostringstream stream;
    const std::tm tm = this->GetUTCTime();

    stream << (tm.tm_year + 1900) << "-";
    stream << std::setw(2) << std::setfill('0') << (tm.tm_mon + 1) << "-";
    stream << std::setw(2) << std::setfill('0') << tm.tm_mday << "T";
    stream << std::setw(2) << std::setfill('0') << tm.tm_hour << ":";
    stream << std::setw(2) << std::setfill('0') << tm.tm_min << ":";
    stream << std::setw(2) << std::setfill('0') << tm.tm_sec << "Z";

    return stream.str();
}

DateTime DateTime::Now() {
    return DateTime(std::chrono::system_clock::now());
}

using BadDatetimeFormatException = std::runtime_error;

std::optional<DateTime> DateTime::ParseDateFromString(std::string_view str, const bool exceptions) {
    
    if (str.empty()) {
        if (exceptions) throw std::invalid_argument("'str': Empty string.");
        return std::nullopt;
    }

    auto [hourOffset, minuteOffset] = DateTime::Now().GetTimezoneOffsetEx();

    // check if the name of the week day is valid:
    const std::string_view dayOfWeek = str.substr(0, 3);
    const std::string_view* it = std::find(std::begin(DateTime::DAY_NAMES), std::end(DateTime::DAY_NAMES), dayOfWeek); // this is used later.
    if (it == std::end(DateTime::DAY_NAMES)) {
        if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
        return std::nullopt;
    }

    str = str.substr(4);

    // check if the month name is valid:
    const std::string_view month = str.substr(0, 3);
    if (std::find(std::begin(DateTime::MONTH_NAMES), std::end(DateTime::MONTH_NAMES), month) == std::end(DateTime::MONTH_NAMES)) {
        if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
        return std::nullopt;
    }

    // parse the timezone:
    std::size_t pos;
    std::string_view timezone = str.substr(21);
    if ((pos = timezone.find(' ')) != std::string_view::npos) 
        timezone = timezone.substr(0, pos);

    if (timezone.substr(0, 3) != "GMT") {
        if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
        return std::nullopt;
    }

    timezone = timezone.substr(3);
    if (!timezone.empty()) {

        try {

            std::string hours { timezone.substr(1, 2) };
            std::string minutes { timezone.substr(3, 2) };
            const std::int32_t k = ((timezone[0] == '+') ? -1 : 1);

            hourOffset += (std::stoi(hours) * k);
            minuteOffset += (std::stoi(minutes) * k);

        }
        catch (const std::exception&) {
            if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
            return std::nullopt;
        }

    }
    
    // parse time and date:
    std::tm tm = { 0 };
    std::stringstream stream { std::string(str) };
    stream.exceptions(std::ios::badbit | std::ios::failbit);

    try { stream >> std::get_time(&tm, "%b %d %Y %H:%M:%S"); }
    catch (const std::ios::failure&) {
        if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
        return std::nullopt;
    }

    tm.tm_isdst = -1;
    std::time_t time = std::mktime(&tm);
    time += std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours(hourOffset)).count();
    time += std::chrono::duration_cast<std::chrono::seconds>(std::chrono::minutes(minuteOffset)).count();

    // check if the week day matches from the week day from the input string:
    if (tm.tm_wday != std::distance(std::begin(DateTime::DAY_NAMES), it)) {
        if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
        return std::nullopt;
    }

    return DateTime(time);
}

std::optional<DateTime> DateTime::ParseDateFromUTCString(std::string_view str, const bool exceptions) {

    if (str.empty()) {
        if (exceptions) throw std::invalid_argument("'str': Empty string.");
        return std::nullopt;
    }

    const auto [hourOffset, minuteOffset] = DateTime::Now().GetTimezoneOffsetEx();

    // check if the name of the week day is valid:
    const std::string_view dayOfWeek = str.substr(0, 3);
    const std::string_view* it = std::find(std::begin(DateTime::DAY_NAMES), std::end(DateTime::DAY_NAMES), dayOfWeek); // this is used later.
    if (it == std::end(DateTime::DAY_NAMES)) {
        if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
        return std::nullopt;
    }

    str = str.substr(5);

    // check if the month name is valid:
    const std::string_view month = str.substr(3, 3);
    if (std::find(std::begin(DateTime::MONTH_NAMES), std::end(DateTime::MONTH_NAMES), month) == std::end(DateTime::MONTH_NAMES)) {
        if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
        return std::nullopt;
    }

    // check if the timezone is GMT+0
    if (str.substr(21) != "GMT") {
        if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
        return std::nullopt;
    }

    // parse time and date:
    std::tm tm = { 0 };
    std::stringstream stream { std::string(str) };
    stream.exceptions(std::ios::badbit | std::ios::failbit);

    try { stream >> std::get_time(&tm, "%d %b %Y %H:%M:%S"); }
    catch (const std::ios::failure&) {
        if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
        return std::nullopt;
    }

    tm.tm_isdst = -1;
    std::time_t time = std::mktime(&tm);
    time += std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours(hourOffset)).count();
    time += std::chrono::duration_cast<std::chrono::seconds>(std::chrono::minutes(minuteOffset)).count();

    // check if the week day matches from the week day from the input string:
    if (tm.tm_wday != std::distance(std::begin(DateTime::DAY_NAMES), it)) {
        if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
        return std::nullopt;
    }

    return DateTime(time);
}

std::optional<DateTime> DateTime::ParseDateFromISO8601String(const std::string_view str, const bool exceptions) {

    if (str.empty()) {
        if (exceptions) throw std::invalid_argument("'str': Empty string.");
        return std::nullopt;
    }

    std::tm tm = { 0 };
    std::stringstream stream { std::string(str) };
    auto [hourOffset, minuteOffset] = DateTime::Now().GetTimezoneOffsetEx();

    try {

        stream >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");

        char ch = stream.get();
        if ((ch != 'Z') && (ch != '+') && (ch != '-'))
            throw std::runtime_error("bad timezone");

        if (ch != 'Z') {

            std::int32_t hours = 0, minutes = 0;
            std::int32_t k = (ch == '+' ? -1 : 1);
            stream >> hours >> ch >> minutes;

            hourOffset += (hours * k);
            minuteOffset += (minutes * k);

        }

    }
    catch (const std::exception&) {
        if (exceptions) throw BadDatetimeFormatException("Bad datetime format.");
        return std::nullopt;
    }

    tm.tm_isdst = -1;
    std::time_t time = std::mktime(&tm);
    time += std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours(hourOffset)).count();
    time += std::chrono::duration_cast<std::chrono::seconds>(std::chrono::minutes(minuteOffset)).count();

    return DateTime(time);
}

DateTime DateTime::Parse(const std::string_view str) {
    return DateTime::ParseDateFromString(str, true).value();
}

DateTime DateTime::ParseUTCDate(const std::string_view str) {
    return DateTime::ParseDateFromUTCString(str, true).value();
}

DateTime DateTime::ParseISO8601Date(const std::string_view str) {
    return DateTime::ParseDateFromISO8601String(str, true).value();
}

std::optional<DateTime> DateTime::TryParse(const std::string_view str) {
    return DateTime::ParseDateFromString(str, false);
}

std::optional<DateTime> DateTime::TryParseUTCDate(const std::string_view str) {
    return DateTime::ParseDateFromUTCString(str, false);
}

std::optional<DateTime> DateTime::TryParseISO8601Date(const std::string_view str) {
    return DateTime::ParseDateFromISO8601String(str, false);
}