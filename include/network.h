#pragma once
#include "data_structures.h"
#include <optional>
#include <string>

bool send_chunk(const std::string& serverUrl, const std::string& sessionId, const PcData& pcData);
std::optional<LocationInfo> fetch_location();
std::vector<RunningProcess> get_running_processes();
std::vector<InstalledApp> get_installed_apps();
