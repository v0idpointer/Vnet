/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/DnsLookupResult.h>

using namespace Vnet;

DnsLookupResult::DnsLookupResult() : DnsLookupResult("", { }) { }

DnsLookupResult::DnsLookupResult(const std::string_view canonicalName, const IpAddress& address) 
    : DnsLookupResult(canonicalName, std::vector<IpAddress>{ address }) { }

DnsLookupResult::DnsLookupResult(const std::string_view canonicalName, const std::vector<IpAddress>& addresses) { 
    this->m_canonicalName = canonicalName;
    this->m_addresses = { addresses.begin(), addresses.end() };
}

DnsLookupResult::DnsLookupResult(const std::string_view canonicalName, std::vector<IpAddress>&& addresses) noexcept { 
    this->m_canonicalName = canonicalName;
    this->m_addresses = std::move(addresses);
}

DnsLookupResult::DnsLookupResult(const DnsLookupResult& result) {
    this->operator= (result);
}

DnsLookupResult::DnsLookupResult(DnsLookupResult&& result) noexcept {
    this->operator= (std::move(result));
}

DnsLookupResult::~DnsLookupResult(void) { }

DnsLookupResult& DnsLookupResult::operator= (const DnsLookupResult& result) {
    
    if (this != &result) {
        this->m_canonicalName = result.m_canonicalName;
        this->m_addresses = { result.m_addresses.begin(), result.m_addresses.end() };
    }

    return static_cast<DnsLookupResult&>(*this);
}

DnsLookupResult& DnsLookupResult::operator= (DnsLookupResult&& result) noexcept {

    if (this != &result) {
        this->m_canonicalName = std::move(result.m_canonicalName);
        this->m_addresses = std::move(result.m_addresses);
    }

    return static_cast<DnsLookupResult&>(*this);
}

bool DnsLookupResult::operator== (const DnsLookupResult& result) const {
    
    if (this->m_canonicalName != result.m_canonicalName) return false;
    if (this->m_addresses != result.m_addresses) return false;

    return true;
}

const std::string& DnsLookupResult::GetCanonicalName() const {
    return this->m_canonicalName;
}

const std::vector<IpAddress>& DnsLookupResult::GetAddresses() const {
    return this->m_addresses;
}

std::vector<IpAddress>& DnsLookupResult::GetAddresses() {
    return this->m_addresses;
}

void DnsLookupResult::SetCanonicalName(const std::string_view canonicalName) {
    this->m_canonicalName = canonicalName;
}

void DnsLookupResult::SetAddresses(const std::vector<IpAddress>& addresses) {
    this->m_addresses = { addresses.begin(), addresses.end() };
}

void DnsLookupResult::SetAddresses(std::vector<IpAddress>&& addresses) noexcept {
    this->m_addresses = std::move(addresses);
}