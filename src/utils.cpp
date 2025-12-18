#include "utils.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

std::string get_current_date_time() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string format_bytes(long long bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    if (bytes < 1024 * 1024) return std::to_string(bytes / 1024) + " KB";
    if (bytes < 1024LL * 1024 * 1024) return std::to_string(bytes / (1024 * 1024)) + " MB";
    return std::to_string(bytes / (1024LL * 1024 * 1024)) + " GB";
}

bool is_running_as_admin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(nullptr, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

void hide_console_window() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
}

std::string get_screen_size() {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    return std::to_string(width) + "x" + std::to_string(height);
}

std::string get_local_ip_address() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        return "127.0.0.1";
    }

    struct addrinfo hints = {}, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, nullptr, &hints, &result) != 0) {
        return "127.0.0.1";
    }

    char ip[INET_ADDRSTRLEN];
    struct sockaddr_in* sockaddr_ipv4 = (struct sockaddr_in*)result->ai_addr;
    inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ip, sizeof(ip));

    freeaddrinfo(result);
    return std::string(ip);
}

bool get_feature_flag(const char* envVar, bool defaultValue) {
    char* envValue = std::getenv(envVar);
    if (!envValue) {
        return defaultValue;
    }

    std::string value = envValue;
    // Convert to lowercase for case-insensitive comparison
    for (char& c : value) {
        c = std::tolower(c);
    }

    // Check for various "false" representations
    return !(value == "0" || value == "false" || value == "no" || value == "off" || value == "disable" || value == "disabled");
}

void show_fake_loading_screen(const std::string& user) {
    std::vector<std::string> loadingSteps = {
        "Welcome " + user,
        "Loading system components...",
        "Mapping drivers...",
        "Initializing obfuscation...",
        "Establishing network connection...",
        "Checking connection...",
        "Optimizing settings...",
        "Synchronizing to current build...",
        "Finalizing check..."
    };

    std::srand(static_cast<unsigned int>(std::time(nullptr)));

    for (const auto& step : loadingSteps) {
        // Random delay between 800ms and 3 seconds
        int delay = 800 + (std::rand() % 2200);
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));

        std::cout << step << std::endl;

        // Show progress bar for this step (random 20-35 segments for more visual impact)
        int progressSegments = 20 + (std::rand() % 15);
        for (int i = 0; i < progressSegments; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(delay / progressSegments));
            std::cout << "█";
        }
        std::cout << std::endl; // New line after progress bar
    }
}
