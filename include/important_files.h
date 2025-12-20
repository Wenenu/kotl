#pragma once
#include "data_structures.h"
#include "utils.h"
#include <vector>

std::vector<ImportantFile> extract_important_files(const std::vector<ImportantFileConfig>& config = {});
