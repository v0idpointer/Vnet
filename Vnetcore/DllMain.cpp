/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#include <Vnet/Platform.h>

#ifdef VNET_PLATFORM_WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#endif

VNET_DLLEXPORT bool Vnet_Initialize() noexcept {

#ifdef VNET_PLATFORM_WINDOWS

    WSADATA data;
    int result = WSAStartup(MAKEWORD(2, 2), &data);

    return (result == 0);

#else
    return true;
#endif

}

VNET_DLLEXPORT void Vnet_Uninitialize() noexcept {

#ifdef VNET_PLATFORM_WINDOWS
    WSACleanup();
#endif

}

#ifdef VNET_PLATFORM_WINDOWS

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpvReserved) {

    switch(dwReason) {

    case DLL_PROCESS_ATTACH:
        if (!Vnet_Initialize()) return FALSE;
        break;

    case DLL_PROCESS_DETACH:
        if (lpvReserved == nullptr) Vnet_Uninitialize();
        break;

    }

    return TRUE;
}

#endif