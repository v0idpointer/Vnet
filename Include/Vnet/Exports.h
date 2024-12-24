/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNET_EXPORTS_H_
#define _VNET_EXPORTS_H_

#include <Vnet/Platform.h>

#ifdef VNET_BUILD_VNETCORE
#define VNETCOREAPI VNET_DLLEXPORT
#else
#define VNETCOREAPI VNET_DLLIMPORT
#endif

#ifdef VNET_BUILD_VNETHTTP
#define VNETHTTPAPI VNET_DLLEXPORT
#else
#define VNETHTTPAPI VNET_DLLIMPORT
#endif

#endif // _VNET_EXPORTS_H_
