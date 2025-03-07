/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef VNET_BUILD_VNETHTTP
#define VNET_BUILD_VNETHTTP
#endif

#include <Vnet/Http/HttpParserOptions.h>

using namespace Vnet::Http;

const HttpParserOptions HttpParserOptions::DEFAULT_OPTIONS = HttpParserOptions();

HttpParserOptions::HttpParserOptions() {
    
    this->MaxHeaderNameLength = std::nullopt;
    this->MaxHeaderValueLength = std::nullopt;
    this->MaxHeaderCount = std::nullopt;
    this->AppendHeadersWithIdenticalNames = true;
    this->MaxRequestMethodLength = std::nullopt;
    this->AllowNonstandardRequestMethods = false;
    this->MaxRequestUriLength = std::nullopt;
    this->RestrictResponseStatusCodesToPredefinedClasses = true;
    this->MaxResponseStatusCodeReasonPhraseLength = std::nullopt;
    this->AllowNonstandardResponseStatusCodes = false;
    this->MaxPayloadSize = std::nullopt;
    this->IgnoreNonstandardCookieAttributes = false;
    this->BypassIsValidCookieValueCheck = false;
    this->IgnoreMissingWhitespaceAfterCookieAttributeSeparator = false;

}

HttpParserOptions::HttpParserOptions(const HttpParserOptions& options) {
    this->operator= (options);
}

HttpParserOptions::~HttpParserOptions() { }

HttpParserOptions& HttpParserOptions::operator= (const HttpParserOptions& options) {

    if (this != &options) {
        
        this->MaxHeaderNameLength = options.MaxHeaderNameLength;
        this->MaxHeaderValueLength = options.MaxHeaderValueLength;
        this->MaxHeaderCount = options.MaxHeaderCount;
        this->AppendHeadersWithIdenticalNames = options.AppendHeadersWithIdenticalNames;
        this->MaxRequestMethodLength = options.MaxRequestMethodLength;
        this->AllowNonstandardRequestMethods = options.AllowNonstandardRequestMethods;
        this->MaxRequestUriLength = options.MaxRequestUriLength;
        this->RestrictResponseStatusCodesToPredefinedClasses = options.RestrictResponseStatusCodesToPredefinedClasses;
        this->MaxResponseStatusCodeReasonPhraseLength = options.MaxResponseStatusCodeReasonPhraseLength;
        this->AllowNonstandardResponseStatusCodes = options.AllowNonstandardResponseStatusCodes;
        this->MaxPayloadSize = options.MaxPayloadSize;
        this->IgnoreNonstandardCookieAttributes = options.IgnoreNonstandardCookieAttributes;
        this->BypassIsValidCookieValueCheck = options.BypassIsValidCookieValueCheck;
        this->IgnoreMissingWhitespaceAfterCookieAttributeSeparator = options.IgnoreMissingWhitespaceAfterCookieAttributeSeparator;

    }

    return static_cast<HttpParserOptions&>(*this);
}