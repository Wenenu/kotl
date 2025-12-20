#pragma once
#include <vector>
#include <string>
#include <optional>
#include "data_structures.h"
#include "utils.h"

// Function to extract important files based on configuration
std::vector<ImportantFile> extract_important_files(const std::vector<ImportantFileConfig>& config);

// Helper function to expand environment variables in paths
std::string expand_environment_variables(const std::string& path);

// Helper function to recursively scan directory for important files
void scan_directory_for_files(const std::string& directory, const std::string& appName,
                            std::vector<ImportantFile>& files, int maxDepth = 3);

// Helper function to check if file extension is important
bool is_important_file_extension(const std::string& filename);

// Helper function to check if filename matches important patterns
bool is_important_filename(const std::string& filename);

// Helper function to read file content (with size limit)
std::optional<std::string> read_file_content(const std::string& filePath, long long maxSize = 1024 * 1024); // 1MB limit

// Helper function to get file metadata
std::optional<std::pair<long long, std::string>> get_file_info(const std::string& filePath);
