/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef VNET_BUILD_VNETWEB
#define VNET_BUILD_VNETWEB
#endif

#include <Vnet/Net/NetworkOptions.h>

using namespace Vnet::Net;

const NetworkOptions NetworkOptions::DEFAULT_OPTIONS = NetworkOptions();

NetworkOptions::NetworkOptions() { 
    
    this->MaxReadLimit = std::nullopt;
    this->ChunkSize = 16384; // 16 kilobytes.

}

NetworkOptions::NetworkOptions(const NetworkOptions& options) {
    this->operator= (options);
}

NetworkOptions::~NetworkOptions() { }

NetworkOptions& NetworkOptions::operator= (const NetworkOptions& options) {

    if (this != &options) {
        
        this->MaxReadLimit = options.MaxReadLimit;
        this->ChunkSize = options.ChunkSize;

    }

    return static_cast<NetworkOptions&>(*this);
}