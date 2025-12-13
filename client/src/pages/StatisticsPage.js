import React, { useState, useEffect } from 'react';
import {
    Box,
    Grid,
    Paper,
    Typography,
    Card,
    CardContent,
    CircularProgress,
    List,
    ListItem,
    ListItemText,
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

const COLORS = ['#4ade80', '#60a5fa', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899'];

function StatisticsPage() {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchStatistics = async () => {
            try {
                setLoading(true);
                const response = await fetch('/api/statistics');
                
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
                <CircularProgress sx={{ color: '#4ade80' }} />
                <Typography sx={{ ml: 2, color: '#94a3b8' }}>Loading statistics...</Typography>
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
                <Typography sx={{ color: '#94a3b8' }}>No statistics available.</Typography>
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
            <Typography variant="h4" sx={{ color: '#4ade80', mb: 3, fontWeight: 700 }}>
                Statistics
            </Typography>

            {/* Summary Cards */}
            <Grid container spacing={3} sx={{ mb: 4 }}>
                <Grid item xs={12} sm={6} md={3}>
                    <Card sx={{ 
                        backgroundColor: '#252b3b', 
                        border: '1px solid #334155', 
                        borderRadius: '12px',
                        height: '100%'
                    }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: '#94a3b8', mb: 1, fontSize: '0.9rem' }}>
                                TOTAL LOGS
                            </Typography>
                            <Typography variant="h3" sx={{ color: '#4ade80', fontWeight: 700 }}>
                                {stats.totalLogs}
                            </Typography>
                            <Typography variant="body2" sx={{ color: '#94a3b8', mt: 1 }}>
                                All collected logs
                            </Typography>
                        </CardContent>
                    </Card>
                </Grid>

                <Grid item xs={12} sm={6} md={3}>
                    <Card sx={{ 
                        backgroundColor: '#252b3b', 
                        border: '1px solid #334155', 
                        borderRadius: '12px',
                        height: '100%'
                    }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: '#94a3b8', mb: 1, fontSize: '0.9rem' }}>
                                IMPORTANT LOGS
                            </Typography>
                            <Typography variant="h3" sx={{ color: '#f59e0b', fontWeight: 700 }}>
                                {stats.importantLogs}
                            </Typography>
                            <Typography variant="body2" sx={{ color: '#94a3b8', mt: 1 }}>
                                {importantPercentage}% of total
                            </Typography>
                        </CardContent>
                    </Card>
                </Grid>

                <Grid item xs={12} sm={6} md={3}>
                    <Card sx={{ 
                        backgroundColor: '#252b3b', 
                        border: '1px solid #334155', 
                        borderRadius: '12px',
                        height: '100%'
                    }}>
                        <CardContent>
                            <Typography variant="h6" sx={{ color: '#94a3b8', mb: 1, fontSize: '0.9rem' }}>
                                DATA COLLECTED
                            </Typography>
                            <Typography variant="h5" sx={{ color: '#8b5cf6', fontWeight: 700 }}>
                                {stats.totals.historyEntries + stats.totals.cookies + stats.totals.processes}
                            </Typography>
                            <Typography variant="body2" sx={{ color: '#94a3b8', mt: 1 }}>
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
                        backgroundColor: '#252b3b', 
                        border: '1px solid #334155', 
                        borderRadius: '12px' 
                    }}>
                        <Typography variant="h6" sx={{ color: '#4ade80', mb: 3, fontWeight: 600 }}>
                            Last 30 Days
                        </Typography>
                        <ResponsiveContainer width="100%" height={300}>
                            <LineChart data={stats.last30Days}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                                <XAxis 
                                    dataKey="date" 
                                    stroke="#94a3b8"
                                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                                    tickFormatter={(value) => {
                                        const date = new Date(value);
                                        return `${date.getMonth() + 1}/${date.getDate()}`;
                                    }}
                                />
                                <YAxis 
                                    stroke="#94a3b8"
                                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                                />
                                <Tooltip 
                                    contentStyle={{ 
                                        backgroundColor: '#1a1f2e', 
                                        border: '1px solid #334155',
                                        borderRadius: '8px',
                                        color: '#e2e8f0'
                                    }}
                                    labelStyle={{ color: '#4ade80' }}
                                />
                                <Legend 
                                    wrapperStyle={{ color: '#94a3b8' }}
                                />
                                <Line 
                                    type="monotone" 
                                    dataKey="count" 
                                    stroke="#4ade80" 
                                    strokeWidth={2}
                                    dot={{ fill: '#4ade80', r: 3 }}
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
                        backgroundColor: '#252b3b', 
                        border: '1px solid #334155', 
                        borderRadius: '12px' 
                    }}>
                        <Typography variant="h6" sx={{ color: '#4ade80', mb: 3, fontWeight: 600, textAlign: 'center' }}>
                            Total Logs Distribution
                        </Typography>
                        <Typography variant="h4" sx={{ color: '#e2e8f0', mb: 2, textAlign: 'center', fontWeight: 700 }}>
                            {stats.totalLogs}
                        </Typography>
                        <ResponsiveContainer width="100%" height={200}>
                            <PieChart>
                                <Pie
                                    data={pieData}
                                    cx="50%"
                                    cy="50%"
                                    innerRadius={60}
                                    outerRadius={90}
                                    paddingAngle={5}
                                    dataKey="value"
                                >
                                    {pieData.map((entry, index) => (
                                        <Cell key={`cell-${index}`} fill={COLORS[index]} />
                                    ))}
                                </Pie>
                                <Tooltip 
                                    contentStyle={{ 
                                        backgroundColor: '#1a1f2e', 
                                        border: '1px solid #334155',
                                        borderRadius: '8px',
                                        color: '#e2e8f0'
                                    }}
                                />
                            </PieChart>
                        </ResponsiveContainer>
                        <Box sx={{ mt: 2, display: 'flex', flexDirection: 'column', gap: 1 }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <Box sx={{ width: 16, height: 16, backgroundColor: '#4ade80', borderRadius: '4px' }} />
                                    <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                                        Important Logs
                                    </Typography>
                                </Box>
                                <Typography variant="body2" sx={{ color: '#4ade80', fontWeight: 600 }}>
                                    {importantPercentage}%
                                </Typography>
                            </Box>
                            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <Box sx={{ width: 16, height: 16, backgroundColor: '#60a5fa', borderRadius: '4px' }} />
                                    <Typography variant="body2" sx={{ color: '#94a3b8' }}>
                                        Regular Logs
                                    </Typography>
                                </Box>
                                <Typography variant="body2" sx={{ color: '#60a5fa', fontWeight: 600 }}>
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
                        backgroundColor: '#252b3b', 
                        border: '1px solid #334155', 
                        borderRadius: '12px' 
                    }}>
                        <Typography variant="h6" sx={{ color: '#4ade80', mb: 3, fontWeight: 600 }}>
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
                                                backgroundColor: '#1a1f2e', 
                                                borderRadius: '8px',
                                                border: '1px solid #334155',
                                                display: 'flex',
                                                alignItems: 'center',
                                                justifyContent: 'space-between'
                                            }}>
                                                <Box>
                                                    <Typography variant="body1" sx={{ color: '#e2e8f0', fontWeight: 500 }}>
                                                        {item.country}
                                                    </Typography>
                                                    <Typography variant="body2" sx={{ color: '#94a3b8', mt: 0.5 }}>
                                                        {percentage}%
                                                    </Typography>
                                                </Box>
                                                <Chip 
                                                    label={item.count} 
                                                    sx={{ 
                                                        backgroundColor: '#4ade80',
                                                        color: '#1a1f2e',
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
                            <Typography sx={{ color: '#94a3b8', p: 2 }}>
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
