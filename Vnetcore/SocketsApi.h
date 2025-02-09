/*
    Vnet: Networking library for C++
    Copyright (c) 2024 V0idPointer
*/

#ifndef _VNETCORE_SOCKETSAPI_H_
#define _VNETCORE_SOCKETSAPI_H_

#include <Vnet/Platform.h>

#ifdef VNET_PLATFORM_WINDOWS
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#endif

#ifndef VNET_PLATFORM_WINDOWS
#define SD_RECEIVE SHUT_RD
#define SD_SEND SHUT_WR
#define SD_BOTH SHUT_RDWR
#define POLLIN EPOLLIN
#define POLLOUT EPOLLOUT
#define POLLERR EPOLLERR
#endif

#if defined(VNET_PLATFORM_WINDOWS) && defined(ERROR)
#undef ERROR
#endif

#endif // _VNETCORE_SOCKETSAPI_H_