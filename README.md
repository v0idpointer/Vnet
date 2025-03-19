# Vnet - a network library for C++20

## --- Under Construction ---
Features and functionalities are being added and refined, so some aspects may be incomplete or subject to change. 

## Components
Vnet consists of multiple components:

- Vnet core library (Vnetcore)
- Vnet HTTP library (Vnethttp)
- Vnet security library (Vnetsec)
- Vnet web library (Vnetweb)

## Building
Vnet uses [xmake](https://xmake.io/#/) as it's build system.

When building on Windows, make sure OpenSSL is installed to ```C:\openssl```. If OpenSSL is installed somewhere else, create a symlink.

OpenSSL is only required when building Vnetsec (and components that depend on Vnetsec).