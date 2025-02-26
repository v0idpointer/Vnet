/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETWEB_NET_NETWORKOPTIONS_H_
#define _VNETWEB_NET_NETWORKOPTIONS_H_

#include <Vnet/Exports.h>

#include <cstdint>
#include <optional>

namespace Vnet::Net {

    struct VNETWEBAPI NetworkOptions {

        /**
         * The maximum number of bytes that a receive operation can read.
         * 
         * Default value: /
         * Used by: HttpStream
         */
        std::optional<std::size_t> MaxReadLimit;

        /**
         * The length (in bytes) of each chunk of data to be sent during a send operation.
         * 
         * Default value: 16384
         * Used by: HttpStream
         */
        std::int32_t ChunkSize;

        /** Default network options. */
        static const NetworkOptions DEFAULT_OPTIONS;

        NetworkOptions(void);
        NetworkOptions(const NetworkOptions& options);
        virtual ~NetworkOptions(void);

        NetworkOptions& operator= (const NetworkOptions& options);

    };

}

#endif // _VNETWEB_NET_NETWORKOPTIONS_H_