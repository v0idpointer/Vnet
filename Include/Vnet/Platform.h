/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNET_PLATFORM_H_
#define _VNET_PLATFORM_H_

#include <Vnet/Platform.h>

#if defined(_WIN32)
#define VNET_PLATFORM_WINDOWS
#elif defined(__APPLE__) || defined(__MACH__)
#define VNET_PLATFORM_MACOS
#elif defined(__linux__)
#define VNET_PLATFORM_LINUX
#else
#error Vnet: Cannot build - unknown platform.
#endif

#ifdef VNET_PLATFORM_WINDOWS
#define VNET_DLLEXPORT __declspec(dllexport)
#define VNET_DLLIMPORT __declspec(dllimport)
#else
#define VNET_DLLEXPORT __attribute__((visibility("default")))
#define VNET_DLLIMPORT
#endif

#endif // _VNET_PLATFORM_H_
