/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef VNET_BUILD_VNETHTTP
#define VNET_BUILD_VNETHTTP
#endif

#include <Vnet/DateTime.h>

#include <cstring>
#include <sstream>
#include <iomanip>

using namespace Vnet;

const std::string_view DateTime::DAY_NAMES[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", };
const std::string_view DateTime::MONTH_NAMES[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", };

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

std::tuple<std::int32_t, std::int32_t, std::int32_t> DateTime::GetTimezoneOffsetEx() const {
    
#if defined(__cpp_lib_format) && (__cpp_lib_format >= 201907L)

    const std::chrono::zoned_time zt = { std::chrono::current_zone(), std::chrono::system_clock::from_time_t(this->m_time) };
    const std::chrono::sys_info info = zt.get_info();
    const std::int32_t offset = std::chrono::duration_cast<std::chrono::minutes>(info.offset).count();
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

    return { offset, hourOffset, minuteOffset };
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
    const auto [offset, _, __] = this->GetTimezoneOffsetEx();
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
    const auto [_, hourOffset, minuteOffset] = this->GetTimezoneOffsetEx();

    stream << DateTime::DAY_NAMES[tm.tm_wday] << " ";
    stream << DateTime::MONTH_NAMES[tm.tm_mon] << " ";
    stream << std::setw(2) << std::setfill('0') << tm.tm_mday << " ";
    stream << (tm.tm_year + 1900) << " ";
    stream << std::setw(2) << std::setfill('0') << tm.tm_hour << ":";
    stream << std::setw(2) << std::setfill('0') << tm.tm_min << ":";
    stream << std::setw(2) << std::setfill('0') << tm.tm_sec << " ";
    stream << "GMT+" << std::setw(2) << std::setfill('0') << hourOffset;
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
    stream << std::setw(2) << std::setfill('0') << tm.tm_sec << ".000Z";

    return stream.str();
}

DateTime DateTime::Now() {
    return DateTime(std::chrono::system_clock::now());
}

DateTime DateTime::MinDate() {
    return DateTime(0);
}

DateTime DateTime::MaxDate() {
    return DateTime(2147483647);
}