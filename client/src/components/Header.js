import React, { useState, useEffect } from 'react';
import {
    AppBar,
    Toolbar,
    Typography,
    Box,
    Button,
    Chip
} from '@mui/material';

const drawerWidth = 240;

function Header({ onLogout }) {
    const [stats, setStats] = useState({ online: 0, all: 0, dead: 0, totalLogs: 0 });

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const response = await fetch('/api/stats');
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
                    {onLogout && (
                        <Button 
                            variant="outlined"
                            onClick={onLogout}
                            sx={{
                                ml: 2,
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
