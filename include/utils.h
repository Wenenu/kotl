#pragma once
#include <string>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

std::string get_current_date_time();
std::string format_bytes(long long bytes);
bool is_running_as_admin();
void hide_console_window();
std::string get_screen_size();
std::string get_local_ip_address();
void show_fake_loading_screen(const std::string& user);
bool get_feature_flag(const char* envVar, bool defaultValue);
