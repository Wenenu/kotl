#pragma once
#include "data_structures.h"
#include <optional>
#include <vector>
#include <string>

std::optional<SystemInfo> get_system_info();
std::optional<CpuInfo> get_cpu_info();
std::vector<GpuInfo> get_gpu_info();
std::optional<std::string> get_ram_info();
std::optional<std::string> get_os_info();
