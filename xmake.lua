-- Vnet: Networking library for C++
-- Copyright (c) 2024-2025 V0idPointer

target("Vnetcore")
    set_kind("shared")
    set_languages("cxx20")
    add_files("Vnetcore/*.cpp")
    add_files("Vnetcore/Sockets/*.cpp")
    add_includedirs("Include")
    add_includedirs("Vnetcore")
    add_defines("VNET_BUILD_VNETCORE")

    if is_plat("windows") then 
        add_links("WS2_32.lib")
    end

    if is_plat("windows") then 
        add_files("Vnetcore/VersionInfo.rc")
    end

target("Vnethttp")
    set_kind("shared")
    set_languages("cxx20")
    add_files("Vnethttp/*.cpp")
    add_files("Vnethttp/Http/*.cpp")
    add_includedirs("Include")
    add_includedirs("Vnethttp")
    add_defines("VNET_BUILD_VNETHTTP")

    if is_plat("windows") then 
        add_files("Vnethttp/VersionInfo.rc")
    end

target("Vnetsec")
    set_kind("shared")
    set_languages("cxx20")
    add_files("Vnetsec/Cryptography/*.cpp")
    add_files("Vnetsec/Cryptography/Certificates/*.cpp")
    add_files("Vnetsec/Security/*.cpp")
    add_includedirs("Include")
    add_includedirs("Vnetsec")
    add_defines("VNET_BUILD_VNETSEC")
    add_deps("Vnetcore")
    add_deps("Vnethttp")

    if is_plat("windows") then 
        add_includedirs("C:/openssl/include") -- symlink if OpenSSL is installed somewhere else.
        add_linkdirs("C:/openssl")
    end

    if is_plat("windows") then
        add_links("libcrypto.lib")
        add_links("libssl.lib")
        add_links("Advapi32.lib")
        add_links("Crypt32.lib")
        add_links("Ncrypt.lib")
    else
        add_links("crypto")
        add_links("ssl")
    end

    if is_plat("windows") then 
        add_files("Vnetsec/VersionInfo.rc")
    end

target("Vnetweb")
    set_kind("shared")
    set_languages("cxx20")
    add_files("Vnetweb/Net/*.cpp")
    add_includedirs("Include")
    add_includedirs("Vnetweb")
    add_defines("VNET_BUILD_VNETWEB")
    add_deps("Vnetcore")
    add_deps("Vnetsec")

    if is_plat("windows") then 
        add_files("Vnetweb/VersionInfo.rc")
    end
