/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETHTTP_HTTP_SAMESITEATTRIBUTE_H_
#define _VNETHTTP_HTTP_SAMESITEATTRIBUTE_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Http {
    
    enum class VNETHTTPAPI SameSiteAttribute : std::int16_t {

        /**
         * Means that the browser sends the cookie only for same-site requests.
         */
        STRICT,

        /**
         * Means that the cookie is not sent on cross-site requests,
         * but is sent when a user is navigating to the origin site 
         * from an external site.
         */
        LAX,

        /**
         * Means that the browser sends the cookie with both cross-site 
         * and same-site requests.
         * 
         * The Secure attribute must also be set when setting this value.
         */
        NONE,

    };

}

#endif // _VNETHTTP_HTTP_SAMESITEATTRIBUTE_H_