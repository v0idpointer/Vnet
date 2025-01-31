/*
    Vnet: Networking library for C++
    Copyright (c) 2024-2025 V0idPointer
*/

#ifndef _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTSTORELOCATION_H_
#define _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTSTORELOCATION_H_

#include <Vnet/Exports.h>

#include <cstdint>

namespace Vnet::Cryptography::Certificates {

    enum class VNETSECURITYAPI CertStoreLocation : std::uint8_t {

        /** Current Service */
        CURRENT_SERVICE,

        /** Current User */
        CURRENT_USER,

        /** Current User Group Policy */
        CURRENT_USER_GP,

        /** Local Machine */
        LOCAL_MACHINE,

        /** Local Machine Enterprise */
        LOCAL_MACHINE_E,

        /** Local Machine Group Policy */
        LOCAL_MACHINE_GP,

        /** Services */
        SERVICES,

        /** Users */
        USERS,

    };

}

#endif // _VNETSEC_CRYPTOGRAPHY_CERTIFICATES_CERTSTORELOCATION_H_