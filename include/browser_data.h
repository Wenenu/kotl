#pragma once
#include "data_structures.h"
#include <utility>
#include <string>

std::pair<std::string, std::vector<SavedPassword>> extract_cookies_with_tool(const std::string& outputDir);
