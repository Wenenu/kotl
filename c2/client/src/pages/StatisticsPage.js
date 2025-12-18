import React, { useState, useEffect } from 'react';
import {
    Box,
    Grid,
    Paper,
    Typography,
    Card,
    CardContent,
    CircularProgress,
    Chip,
} from '@mui/material';
import {
    LineChart,
    Line,
    PieChart,
    Pie,
    Cell,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
    ResponsiveContainer,
} from 'recharts';

function StatisticsPage() {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [themeColors, setThemeColors] = useState({
        primary: '#4ade80',
        secondary: '#60a5fa',
        background: '#1a1f2e',
        paper: '#252b3b',
        textPrimary: '#e2e8f0',
        textSecondary: '#94a3b8',
    });

    // Load theme colors from localStorage
    useEffect(() => {
        const savedSettings = localStorage.getItem('themeSettings');
        if (savedSettings) {
            try {
                const parsed = JSON.parse(savedSettings);
                setThemeColors(prev => ({
                    ...prev,
                    primary: parsed.primary || prev.primary,
                    secondary: parsed.secondary || prev.secondary,
                    background: parsed.background || prev.background,
                    paper: parsed.paper || prev.paper,
                    textPrimary: parsed.textPrimary || prev.textPrimary,
                    textSecondary: parsed.textSecondary || prev.textSecondary,
                }));
            } catch (e) {
                console.error('Error loading theme settings:', e);
            }
        }
    }, []);

    // Chart colors based on theme
    const COLORS = [themeColors.primary, themeColors.secondary, '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'];

    useEffect(() => {
        const fetchStatistics = async () => {
            try {
                setLoading(true);
                const token = localStorage.getItem('authToken');
                
                const response = await fetch('/api/statistics', {
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json',
                    },
                });
                
                // Check if response is HTML (which means route wasn't found)
                const contentType = response.headers.get('content-type');
                if (contentType && !contentType.includes('application/json')) {
                    const text = await response.text();
                    console.error('Received non-JSON response:', text.substring(0, 200));
                    throw new Error('Server returned HTML instead of JSON. Make sure the backend server is running and restarted.');
                }
                
                if (!response.ok) {
                    throw new Error(`Server responded with status: ${response.status}`);
                }
                const data = await response.json();
                setStats(data);
                setError(null);
            } catch (err) {
                console.error("Failed to fetch statistics:", err);
                setError(`Error fetching statistics: ${err.message}`);
            } finally {
                setLoading(false);
            }
        };

        fetchStatistics();
        const intervalId = setInterval(fetchStatistics, 30000); // Refresh every 30 seconds
        return () => clearInterval(intervalId);
    }, []);

    if (loading) {
        return (
            <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}>
                <CircularProgress sx={{ color: themeColors.primary }} />
                <Typography sx={{ ml: 2, color: themeColors.textSecondary }}>Loading statistics...</Typography>
            </Box>
        );
    }

    if (error) {
        return (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                <Typography color="error">{error}</Typography>
            </Box>
        );
    }

    if (!stats) {
        return (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                <Typography sx={{ color: themeColors.textSecondary }}>No statistics available.</Typography>
            </Box>
        );
    }

    // Prepare data for pie chart
    const pieData = [
        { name: 'Important Logs', value: stats.importantLogs },
        { name: 'Regular Logs', value: stats.regularLogs }
    ];

    const importantPercentage = stats.totalLogs > 0 
        ? ((stats.importantLogs / stats.totalLogs) * 100).toFixed(2)
        : 0;
    const regularPercentage = stats.totalLogs > 0 
        ? ((stats.regularLogs / stats.totalLogs) * 100).toFixed(2)
        : 0;

    return (
        <Box sx={{ p: 3 }}>
            <Typography variant="h4" sx={{ color: themeColors.primary, mb: 3, fontWeight: 700 }}>
                Statistics
            </Typography>

            {/* Summary Cards */}
            <Grid container spacing={3} sx={{ mb: 4 }}>
                <Grid item xs={12} sm={6} md={3}>
                    <Card sx={{ 
                        backgroundColor: themeColors.paper, 
                        border: `1px solid ${themeColors.textSecondary}33`, 
                        borderRadius: '12px',
                        height: '100%'
                    }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: themeColors.textSecondary, mb: 1, fontSize: '0.9rem' }}>
                                TOTAL LOGS
                            </Typography>
                            <Typography variant="h3" sx={{ color: themeColors.primary, fontWeight: 700 }}>
                                {stats.totalLogs}
                            </Typography>
                            <Typography variant="body2" sx={{ color: themeColors.textSecondary, mt: 1 }}>
                                All collected logs
                            </Typography>
                        </CardContent>
                    </Card>
                </Grid>

                <Grid item xs={12} sm={6} md={3}>
                    <Card sx={{ 
                        backgroundColor: themeColors.paper, 
                        border: `1px solid ${themeColors.textSecondary}33`, 
                        borderRadius: '12px',
                        height: '100%'
                    }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: themeColors.textSecondary, mb: 1, fontSize: '0.9rem' }}>
                                IMPORTANT LOGS
                            </Typography>
                            <Typography variant="h3" sx={{ color: '#f59e0b', fontWeight: 700 }}>
                                {stats.importantLogs}
                            </Typography>
                            <Typography variant="body2" sx={{ color: themeColors.textSecondary, mt: 1 }}>
                                {importantPercentage}% of total
                            </Typography>
                        </CardContent>
                    </Card>
                </Grid>

                <Grid item xs={12} sm={6} md={3}>
                    <Card sx={{ 
                        backgroundColor: themeColors.paper, 
                        border: `1px solid ${themeColors.textSecondary}33`, 
                        borderRadius: '12px',
                        height: '100%'
                    }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: themeColors.textSecondary, mb: 1, fontSize: '0.9rem' }}>
                                DATA COLLECTED
                            </Typography>
                            <Typography variant="h5" sx={{ color: themeColors.secondary, fontWeight: 700 }}>
                                {stats.totals.historyEntries + stats.totals.cookies + stats.totals.processes}
                            </Typography>
                            <Typography variant="body2" sx={{ color: themeColors.textSecondary, mt: 1 }}>
                                History, cookies, processes
                            </Typography>
                        </CardContent>
                    </Card>
                </Grid>
            </Grid>

            {/* Charts and Country Distribution */}
            <Grid container spacing={3}>
                {/* Last 30 Days Chart */}
                <Grid item xs={12} md={8}>
                    <Paper sx={{ 
                        p: 3, 
                        backgroundColor: themeColors.paper, 
                        border: `1px solid ${themeColors.textSecondary}33`, 
                        borderRadius: '12px' 
                    }}>
                        <Typography variant="h6" sx={{ color: themeColors.primary, mb: 3, fontWeight: 600 }}>
                            Last 30 Days
                        </Typography>
                        <ResponsiveContainer width="100%" height={300}>
                            <LineChart data={stats.last30Days}>
                                <CartesianGrid strokeDasharray="3 3" stroke={`${themeColors.textSecondary}33`} />
                                <XAxis 
                                    dataKey="date" 
                                    stroke={themeColors.textSecondary}
                                    tick={{ fill: themeColors.textSecondary, fontSize: 12 }}
                                    tickFormatter={(value) => {
                                        const date = new Date(value);
                                        return `${date.getMonth() + 1}/${date.getDate()}`;
                                    }}
                                />
                                <YAxis 
                                    stroke={themeColors.textSecondary}
                                    tick={{ fill: themeColors.textSecondary, fontSize: 12 }}
                                />
                                <Tooltip 
                                    contentStyle={{ 
                                        backgroundColor: themeColors.background, 
                                        border: `1px solid ${themeColors.textSecondary}33`,
                                        borderRadius: '8px',
                                        color: themeColors.textPrimary
                                    }}
                                    labelStyle={{ color: themeColors.primary }}
                                />
                                <Legend 
                                    wrapperStyle={{ color: themeColors.textSecondary }}
                                />
                                <Line 
                                    type="monotone" 
                                    dataKey="count" 
                                    stroke={themeColors.primary} 
                                    strokeWidth={2}
                                    dot={{ fill: themeColors.primary, r: 3 }}
                                    name="Logs"
                                />
                            </LineChart>
                        </ResponsiveContainer>
                    </Paper>
                </Grid>

                {/* Pie Chart */}
                <Grid item xs={12} md={4}>
                    <Paper sx={{ 
                        p: 3, 
                        backgroundColor: themeColors.paper, 
                        border: `1px solid ${themeColors.textSecondary}33`, 
                        borderRadius: '12px' 
                    }}>
                        <Typography variant="h6" sx={{ color: themeColors.primary, mb: 1, fontWeight: 600, textAlign: 'center' }}>
                            Total Logs Distribution
                        </Typography>
                        <Typography variant="h4" sx={{ color: themeColors.textPrimary, mb: 1, textAlign: 'center', fontWeight: 700 }}>
                            {stats.totalLogs}
                        </Typography>
                        <ResponsiveContainer width="100%" height={180}>
                            <PieChart>
                                <Pie
                                    data={pieData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={90}
                                    paddingAngle={2}
                                    dataKey="value"
                                >
                                    {pieData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index]} />
                                    ))}
                                </Pie>
                                <Tooltip 
                                    contentStyle={{ 
                                        backgroundColor: themeColors.background, 
                                        border: `1px solid ${themeColors.textSecondary}33`,
                                        borderRadius: '8px',
                                        color: themeColors.textPrimary
                                    }}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                        <Box sx={{ mt: 1, display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <Box sx={{ width: 16, height: 16, backgroundColor: themeColors.primary, borderRadius: '4px' }} />
                                    <Typography variant="body2" sx={{ color: themeColors.textSecondary }}>
                                        Important Logs
                                    </Typography>
                                </Box>
                                <Typography variant="body2" sx={{ color: themeColors.primary, fontWeight: 600 }}>
                                    {importantPercentage}%
                                </Typography>
                            </Box>
                            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <Box sx={{ width: 16, height: 16, backgroundColor: themeColors.secondary, borderRadius: '4px' }} />
                                    <Typography variant="body2" sx={{ color: themeColors.textSecondary }}>
                                        Regular Logs
                                    </Typography>
                                </Box>
                                <Typography variant="body2" sx={{ color: themeColors.secondary, fontWeight: 600 }}>
                                    {regularPercentage}%
                                </Typography>
                            </Box>
                        </Box>
                    </Paper>
                </Grid>

                {/* Country Distribution */}
                <Grid item xs={12}>
                    <Paper sx={{ 
                        p: 3, 
                        backgroundColor: themeColors.paper, 
                        border: `1px solid ${themeColors.textSecondary}33`, 
                        borderRadius: '12px' 
                    }}>
                        <Typography variant="h6" sx={{ color: themeColors.primary, mb: 3, fontWeight: 600 }}>
                            Data by Country
                        </Typography>
                        {stats.countryDistribution.length > 0 ? (
                            <Grid container spacing={2}>
                                {stats.countryDistribution.map((item, index) => {
                                    const percentage = stats.totalLogs > 0 
                                        ? ((item.count / stats.totalLogs) * 100).toFixed(2)
                                        : 0;
                                    return (
                                        <Grid item xs={12} sm={6} md={4} lg={3} key={item.country}>
                                            <Box sx={{ 
                                                p: 2, 
                                                backgroundColor: themeColors.background, 
                                                borderRadius: '8px',
                                                border: `1px solid ${themeColors.textSecondary}33`,
                                                display: 'flex',
                                                alignItems: 'center',
                                                justifyContent: 'space-between'
                                            }}>
                                                <Box>
                                                    <Typography variant="body1" sx={{ color: themeColors.textPrimary, fontWeight: 500 }}>
                                                        {item.country}
                                                    </Typography>
                                                    <Typography variant="body2" sx={{ color: themeColors.textSecondary, mt: 0.5 }}>
                                                        {percentage}%
                                                    </Typography>
                                                </Box>
                                                <Chip 
                                                    label={item.count} 
                                                    sx={{ 
                                                        backgroundColor: themeColors.primary,
                                                        color: themeColors.background,
                                                        fontWeight: 700,
                                                        minWidth: '60px'
                                                    }} 
                                                />
                                            </Box>
                                        </Grid>
                                    );
                                })}
                            </Grid>
                        ) : (
                            <Typography sx={{ color: themeColors.textSecondary, p: 2 }}>
                                No country data available.
                            </Typography>
                        )}
                    </Paper>
                </Grid>
            </Grid>
        </Box>
    );
}

export default StatisticsPage;
