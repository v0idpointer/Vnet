-- Vnet: Networking library for C++
-- Copyright (c) 2024 V0idPointer

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

target("Vnethttp")
    set_kind("shared")
    set_languages("cxx20")
    add_files("Vnethttp/*.cpp")
    add_files("Vnethttp/Http/*.cpp")
    add_includedirs("Include")
    add_includedirs("Vnethttp")
    add_defines("VNET_BUILD_VNETHTTP")
