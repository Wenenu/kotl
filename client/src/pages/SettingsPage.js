import React, { useState, useEffect } from 'react';
import {
    Box,
    Paper,
    Typography,
    TextField,
    Button,
    Grid,
    Divider,
    Switch,
    FormControlLabel,
    Slider,
    Select,
    MenuItem,
    FormControl,
    InputLabel,
    Alert,
    Snackbar,
} from '@mui/material';

const PRESET_THEMES = {
    default: {
        name: 'Default (Mellow Green)',
        primary: '#4ade80',
        secondary: '#60a5fa',
        background: '#1a1f2e',
        paper: '#252b3b',
        textPrimary: '#e2e8f0',
        textSecondary: '#94a3b8',
    },
    purple: {
        name: 'Purple',
        primary: '#a855f7',
        secondary: '#ec4899',
        background: '#1e1b2e',
        paper: '#2a2540',
        textPrimary: '#f3e8ff',
        textSecondary: '#c4b5fd',
    },
    blue: {
        name: 'Ocean Blue',
        primary: '#3b82f6',
        secondary: '#06b6d4',
        background: '#0f172a',
        paper: '#1e293b',
        textPrimary: '#e0e7ff',
        textSecondary: '#94a3b8',
    },
    red: {
        name: 'Crimson',
        primary: '#ef4444',
        secondary: '#f97316',
        background: '#1f1a1a',
        paper: '#2d2525',
        textPrimary: '#fee2e2',
        textSecondary: '#fca5a5',
    },
    orange: {
        name: 'Amber',
        primary: '#f59e0b',
        secondary: '#eab308',
        background: '#1f1a0f',
        paper: '#2d2515',
        textPrimary: '#fef3c7',
        textSecondary: '#fde68a',
    },
    cyan: {
        name: 'Cyan',
        primary: '#06b6d4',
        secondary: '#8b5cf6',
        background: '#0f1f2e',
        paper: '#1a2b3b',
        textPrimary: '#e0f2fe',
        textSecondary: '#bae6fd',
    },
};

function SettingsPage() {
    const [settings, setSettings] = useState({
        primary: '#3b82f6',
        secondary: '#06b6d4',
        background: '#0f172a',
        paper: '#1e293b',
        textPrimary: '#e0e7ff',
        textSecondary: '#94a3b8',
        borderRadius: 12,
        fontFamily: 'Inter',
        enableAnimations: true,
    });

    const [snackbar, setSnackbar] = useState({ open: false, message: '' });

    useEffect(() => {
        // Load saved settings from localStorage
        const savedSettings = localStorage.getItem('themeSettings');
        if (savedSettings) {
            try {
                const parsed = JSON.parse(savedSettings);
                setSettings(prev => ({ ...prev, ...parsed }));
            } catch (e) {
                console.error('Error loading theme settings:', e);
            }
        }
    }, []);

    const handleColorChange = (colorKey) => (color) => {
        setSettings(prev => ({
            ...prev,
            [colorKey]: color,
        }));
    };

    const handleSliderChange = (key) => (event, value) => {
        setSettings(prev => ({
            ...prev,
            [key]: value,
        }));
    };

    const handlePresetTheme = (preset) => {
        setSettings(prev => ({
            ...prev,
            ...preset,
        }));
    };

    const handleSave = () => {
        localStorage.setItem('themeSettings', JSON.stringify(settings));
        setSnackbar({ open: true, message: 'Settings saved! Refresh the page to apply changes.' });
        // Trigger a custom event to notify App.js to reload theme
        window.dispatchEvent(new CustomEvent('themeUpdated'));
    };

    const handleReset = () => {
        const defaultSettings = {
            primary: '#3b82f6',
            secondary: '#06b6d4',
            background: '#0f172a',
            paper: '#1e293b',
            textPrimary: '#e0e7ff',
            textSecondary: '#94a3b8',
            borderRadius: 12,
            fontFamily: 'Inter',
            enableAnimations: true,
        };
        setSettings(defaultSettings);
        localStorage.setItem('themeSettings', JSON.stringify(defaultSettings));
        setSnackbar({ open: true, message: 'Settings reset to default!' });
        window.dispatchEvent(new CustomEvent('themeUpdated'));
    };

    const ColorPickerField = ({ label, value, onChange }) => (
        <Box>
            <Typography variant="body2" sx={{ mb: 1, color: 'text.secondary' }}>
                {label}
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <input
                    type="color"
                    value={value}
                    onChange={(e) => onChange(e.target.value)}
                    style={{
                        width: '60px',
                        height: '40px',
                        border: 'none',
                        borderRadius: '8px',
                        cursor: 'pointer',
                    }}
                />
                <TextField
                    size="small"
                    value={value}
                    onChange={(e) => onChange(e.target.value)}
                    sx={{ width: 120 }}
                    placeholder="#000000"
                />
            </Box>
        </Box>
    );

    return (
        <Box>
            <Typography variant="h4" sx={{ mb: 3, fontWeight: 700 }}>
                Settings
            </Typography>

            <Grid container spacing={3}>
                {/* Preset Themes */}
                <Grid item xs={12}>
                    <Paper sx={{ p: 3 }}>
                        <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                            Preset Themes
                        </Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
                            {Object.entries(PRESET_THEMES).map(([key, theme]) => (
                                <Button
                                    key={key}
                                    variant="outlined"
                                    onClick={() => handlePresetTheme(theme)}
                                    sx={{
                                        minWidth: 150,
                                        borderColor: theme.primary,
                                        color: theme.primary,
                                        '&:hover': {
                                            borderColor: theme.primary,
                                            backgroundColor: `${theme.primary}15`,
                                        },
                                    }}
                                >
                                    {theme.name}
                                </Button>
                            ))}
                        </Box>
                    </Paper>
                </Grid>

                {/* Color Customization */}
                <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 3 }}>
                        <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                            Primary Colors
                        </Typography>
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                            <ColorPickerField
                                label="Primary Color"
                                value={settings.primary}
                                onChange={handleColorChange('primary')}
                            />
                            <ColorPickerField
                                label="Secondary Color"
                                value={settings.secondary}
                                onChange={handleColorChange('secondary')}
                            />
                        </Box>
                    </Paper>
                </Grid>

                <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 3 }}>
                        <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                            Background Colors
                        </Typography>
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                            <ColorPickerField
                                label="Background"
                                value={settings.background}
                                onChange={handleColorChange('background')}
                            />
                            <ColorPickerField
                                label="Paper/Card Background"
                                value={settings.paper}
                                onChange={handleColorChange('paper')}
                            />
                        </Box>
                    </Paper>
                </Grid>

                <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 3 }}>
                        <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                            Text Colors
                        </Typography>
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                            <ColorPickerField
                                label="Primary Text"
                                value={settings.textPrimary}
                                onChange={handleColorChange('textPrimary')}
                            />
                            <ColorPickerField
                                label="Secondary Text"
                                value={settings.textSecondary}
                                onChange={handleColorChange('textSecondary')}
                            />
                        </Box>
                    </Paper>
                </Grid>

                {/* Other Customization */}
                <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 3 }}>
                        <Typography variant="h6" sx={{ mb: 2, fontWeight: 600 }}>
                            Appearance
                        </Typography>
                        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                            <Box>
                                <Typography variant="body2" sx={{ mb: 1, color: 'text.secondary' }}>
                                    Border Radius: {settings.borderRadius}px
                                </Typography>
                                <Slider
                                    value={settings.borderRadius}
                                    onChange={handleSliderChange('borderRadius')}
                                    min={0}
                                    max={24}
                                    step={1}
                                    marks={[
                                        { value: 0, label: '0px' },
                                        { value: 8, label: '8px' },
                                        { value: 12, label: '12px' },
                                        { value: 16, label: '16px' },
                                        { value: 24, label: '24px' },
                                    ]}
                                />
                            </Box>

                            <FormControl fullWidth>
                                <InputLabel>Font Family</InputLabel>
                                <Select
                                    value={settings.fontFamily}
                                    label="Font Family"
                                    onChange={(e) => setSettings(prev => ({ ...prev, fontFamily: e.target.value }))}
                                >
                                    <MenuItem value="Inter">Inter</MenuItem>
                                    <MenuItem value="Roboto">Roboto</MenuItem>
                                    <MenuItem value="Open Sans">Open Sans</MenuItem>
                                    <MenuItem value="Lato">Lato</MenuItem>
                                    <MenuItem value="Montserrat">Montserrat</MenuItem>
                                    <MenuItem value="Poppins">Poppins</MenuItem>
                                    <MenuItem value="Raleway">Raleway</MenuItem>
                                </Select>
                            </FormControl>

                            <FormControlLabel
                                control={
                                    <Switch
                                        checked={settings.enableAnimations}
                                        onChange={(e) => setSettings(prev => ({ ...prev, enableAnimations: e.target.checked }))}
                                    />
                                }
                                label="Enable Animations"
                            />
                        </Box>
                    </Paper>
                </Grid>

                {/* Action Buttons */}
                <Grid item xs={12}>
                    <Paper sx={{ p: 3 }}>
                        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
                            <Button
                                variant="outlined"
                                onClick={handleReset}
                                sx={{ minWidth: 120 }}
                            >
                                Reset to Default
                            </Button>
                            <Button
                                variant="contained"
                                onClick={handleSave}
                                sx={{ minWidth: 120 }}
                            >
                                Save Settings
                            </Button>
                        </Box>
                    </Paper>
                </Grid>
            </Grid>

            <Snackbar
                open={snackbar.open}
                autoHideDuration={4000}
                onClose={() => setSnackbar({ open: false, message: '' })}
                anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
            >
                <Alert severity="success" onClose={() => setSnackbar({ open: false, message: '' })}>
                    {snackbar.message}
                </Alert>
            </Snackbar>
        </Box>
    );
}

export default SettingsPage;
