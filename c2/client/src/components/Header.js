import React, { useState, useEffect } from 'react';
import {
    AppBar,
    Toolbar,
    Typography,
    Box,
    Button,
    Chip,
    Tooltip,
    IconButton
} from '@mui/material';
import {
    Key as KeyIcon,
    ContentCopy as CopyIcon,
    Check as CheckIcon
} from '@mui/icons-material';

const drawerWidth = 240;

function Header({ onLogout }) {
    const [stats, setStats] = useState({ online: 0, all: 0, dead: 0, totalLogs: 0 });
    const [loginKey, setLoginKey] = useState('');
    const [copied, setCopied] = useState(false);

    useEffect(() => {
        // Get login key from localStorage
        const userInfo = JSON.parse(localStorage.getItem('userInfo') || '{}');
        if (userInfo.username) {
            setLoginKey(userInfo.username);
        }

        const fetchStats = async () => {
            try {
                const token = localStorage.getItem('authToken');
                if (!token) {
                    return; // Don't fetch if not authenticated
                }
                
                const response = await fetch('/api/stats', {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
                if (response.ok) {
                    const jsonData = await response.json();
                    setStats(jsonData);
                }
            } catch (err) {
                console.error("Could not fetch stats", err);
            }
        };

        const intervalId = setInterval(fetchStats, 5000);
        fetchStats();

        return () => clearInterval(intervalId);
    }, []);

    const handleCopyKey = async () => {
        if (!loginKey) return;
        
        try {
            await navigator.clipboard.writeText(loginKey);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = loginKey;
            textArea.style.position = 'fixed';
            textArea.style.opacity = '0';
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
            } catch (fallbackErr) {
                console.error('Fallback copy failed:', fallbackErr);
            }
            document.body.removeChild(textArea);
        }
    };

    return (
        <AppBar
            position="fixed"
            sx={{ 
                width: `calc(100% - ${drawerWidth}px)`, 
                ml: `${drawerWidth}px`,
                backgroundColor: '#0a0a0a',
                borderBottom: '1px solid #333333',
            }}
        >
            <Toolbar>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, flexGrow: 1 }}>
                    <Chip 
                        label={`Logs: ${stats.totalLogs}`} 
                        size="small"
                    />
                </Box>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {loginKey && (
                        <Tooltip 
                            title={copied ? 'Copied!' : loginKey}
                            arrow
                            placement="bottom"
                        >
                            <IconButton
                                onClick={handleCopyKey}
                                sx={{
                                    color: '#94a3b8',
                                    '&:hover': {
                                        color: '#4ade80',
                                        backgroundColor: 'rgba(74, 222, 128, 0.1)',
                                    },
                                }}
                            >
                                {copied ? <CheckIcon fontSize="small" /> : <KeyIcon fontSize="small" />}
                            </IconButton>
                        </Tooltip>
                    )}
                    {onLogout && (
                        <Button 
                            variant="outlined"
                            onClick={onLogout}
                            sx={{
                                borderColor: '#334155',
                                color: '#e2e8f0',
                                borderRadius: '8px',
                                '&:hover': {
                                    borderColor: '#4ade80',
                                    backgroundColor: 'rgba(74, 222, 128, 0.1)',
                                },
                            }}
                        >
                            Logout
                        </Button>
                    )}
                </Box>
            </Toolbar>
        </AppBar>
    );
}

export default Header;
