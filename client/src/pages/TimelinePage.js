import React, { useState, useEffect } from 'react';
import {
    Box,
    Paper,
    Typography,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableRow,
} from '@mui/material';

function TimelinePage() {
    const [userInfo, setUserInfo] = useState(null);
    const [currentTime, setCurrentTime] = useState(new Date());

    useEffect(() => {
        // Get stored user info
        const stored = localStorage.getItem('userInfo');
        if (stored) {
            setUserInfo(JSON.parse(stored));
        }

        // Update current time every second
        const timeInterval = setInterval(() => {
            setCurrentTime(new Date());
        }, 1000);

        return () => clearInterval(timeInterval);
    }, []);

    const formatDate = (dateString) => {
        if (!dateString) return 'N/A';
        const date = new Date(dateString);
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            timeZoneName: 'short'
        });
    };

    const formatCurrentTime = () => {
        return currentTime.toLocaleString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            timeZoneName: 'short'
        });
    };

    return (
        <Box sx={{ p: 3 }}>
            <Typography variant="h4" gutterBottom sx={{ color: '#4ade80', mb: 3, fontWeight: 600 }}>
                User Information
            </Typography>

            <Paper sx={{ backgroundColor: '#252b3b', border: '1px solid #334155', borderRadius: '12px', overflow: 'hidden', mb: 3 }}>
                <TableContainer>
                    <Table>
                        <TableBody>
                            <TableRow>
                                <TableCell sx={{ color: '#e2e8f0', fontWeight: 500 }}>Username</TableCell>
                                <TableCell sx={{ color: '#94a3b8' }}>
                                    {userInfo?.username || 'Not set'}
                                </TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell sx={{ color: '#e2e8f0', fontWeight: 500 }}>Last Login</TableCell>
                                <TableCell sx={{ color: '#94a3b8' }}>
                                    {userInfo?.loginTime ? formatDate(userInfo.loginTime) : 'N/A'}
                                </TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell sx={{ color: '#e2e8f0', fontWeight: 500 }}>Current Time</TableCell>
                                <TableCell sx={{ color: '#94a3b8' }}>
                                    {formatCurrentTime()}
                                </TableCell>
                            </TableRow>
                        </TableBody>
                    </Table>
                </TableContainer>
            </Paper>
        </Box>
    );
}

export default TimelinePage;
