import React, { useState } from 'react';
import {
    Box,
    Paper,
    TextField,
    Button,
    Typography,
    Container,
    IconButton,
    InputAdornment,
    Tooltip,
    Fade,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import CheckIcon from '@mui/icons-material/Check';
import KeyIcon from '@mui/icons-material/Key';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import LoginIcon from '@mui/icons-material/Login';

// Generate a random 20-character key with uppercase and lowercase letters
const generateAccessKey = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let key = '';
    for (let i = 0; i < 20; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
};

function Login({ onLogin }) {
    const [accessKey, setAccessKey] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [isRegisterView, setIsRegisterView] = useState(false);
    const [generatedKey, setGeneratedKey] = useState('');
    const [copied, setCopied] = useState(false);
    const [registerSuccess, setRegisterSuccess] = useState(false);

    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        if (!accessKey) {
            setError('Please enter your access key');
            setLoading(false);
            return;
        }

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ key: accessKey }),
                credentials: 'same-origin',
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Server error' }));
                setError(errorData.message || `Server error: ${response.status}`);
                setLoading(false);
                return;
            }

            const data = await response.json();

            // Get location info
            let locationInfo = null;
            try {
                const locationResponse = await fetch('https://freeipapi.com/api/json');
                if (locationResponse.ok) {
                    locationInfo = await locationResponse.json();
                }
            } catch (err) {
                console.error('Error fetching location:', err);
            }

            // Store user info
            const userInfo = {
                username: data.username,
                loginTime: new Date().toISOString(),
                location: locationInfo
            };
            localStorage.setItem('userInfo', JSON.stringify(userInfo));
            localStorage.setItem('authToken', data.token);
            
            onLogin();
        } catch (err) {
            console.error('Login error:', err);
            if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
                setError('Failed to connect to server. Make sure the backend server is running on port 3001.');
            } else {
                setError(`Connection error: ${err.message}`);
            }
            setLoading(false);
        }
    };

    const handleRegister = async () => {
        setError('');
        setLoading(true);

        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ key: generatedKey }),
                credentials: 'same-origin',
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Server error' }));
                setError(errorData.message || `Server error: ${response.status}`);
                setLoading(false);
                return;
            }

            setRegisterSuccess(true);
            setLoading(false);
        } catch (err) {
            console.error('Register error:', err);
            if (err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
                setError('Failed to connect to server. Make sure the backend server is running on port 3001.');
            } else {
                setError(`Connection error: ${err.message}`);
            }
            setLoading(false);
        }
    };

    const handleGenerateKey = () => {
        const newKey = generateAccessKey();
        setGeneratedKey(newKey);
        setCopied(false);
        setRegisterSuccess(false);
        setError('');
    };

    const handleCopyKey = () => {
        navigator.clipboard.writeText(generatedKey);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const switchToRegister = () => {
        setIsRegisterView(true);
        setError('');
        setAccessKey('');
        handleGenerateKey();
    };

    const switchToLogin = () => {
        setIsRegisterView(false);
        setError('');
        setGeneratedKey('');
        setRegisterSuccess(false);
    };

    const useGeneratedKeyToLogin = () => {
        setAccessKey(generatedKey);
        switchToLogin();
    };

    return (
            <Box
                sx={{
                    minHeight: '100vh',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    background: 'linear-gradient(135deg, #0f172a 0%, #1e293b 100%)',
                }}
            >
                <Container maxWidth="sm">
                    <Paper
                        sx={{
                            p: 4,
                            display: 'flex',
                            flexDirection: 'column',
                            alignItems: 'center',
                            gap: 3,
                            backgroundColor: '#1e293b',
                            border: '1px solid #334155',
                            borderRadius: '16px',
                        }}
                    >
                    {/* Icon */}
                    <Box
                        sx={{
                            width: 64,
                            height: 64,
                            borderRadius: '50%',
                            backgroundColor: '#3b82f6',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            mb: 1,
                        }}
                    >
                        <KeyIcon sx={{ fontSize: 32, color: '#fff' }} />
                    </Box>

                    <Typography
                        variant="h5"
                        sx={{
                            color: '#e0e7ff',
                            fontWeight: 600,
                            textAlign: 'center',
                        }}
                    >
                        {isRegisterView ? 'Generate Access Key' : 'Sign In'}
                    </Typography>

                    {error && (
                        <Typography
                            variant="body2"
                            sx={{
                                color: '#ef4444',
                                textAlign: 'center',
                                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                                padding: '8px 16px',
                                borderRadius: '8px',
                                width: '100%',
                            }}
                        >
                            {error}
                        </Typography>
                    )}

                    {!isRegisterView ? (
                        // LOGIN VIEW
                    <Box
                        component="form"
                            onSubmit={handleLogin}
                        sx={{
                            width: '100%',
                            display: 'flex',
                            flexDirection: 'column',
                            gap: 2,
                        }}
                    >
                        <TextField
                                label="Access Key"
                                type="password"
                                value={accessKey}
                                onChange={(e) => setAccessKey(e.target.value)}
                            fullWidth
                            autoFocus
                                placeholder="Enter your 20-character access key"
                            sx={{
                                '& .MuiInputBase-input': {
                                    color: '#e0e7ff',
                                        fontFamily: 'monospace',
                                        letterSpacing: '1px',
                                },
                                '& .MuiInputLabel-root': {
                                    color: '#94a3b8',
                                },
                                    '& .MuiOutlinedInput-root': {
                                        '& fieldset': {
                                            borderColor: '#475569',
                                        },
                                        '&:hover fieldset': {
                                            borderColor: '#64748b',
                                        },
                                        '&.Mui-focused fieldset': {
                                            borderColor: '#3b82f6',
                                        },
                                },
                            }}
                        />
                        <Button
                            type="submit"
                            variant="contained"
                            fullWidth
                            disabled={loading}
                                startIcon={<LoginIcon />}
                            sx={{
                                    mt: 1,
                                py: 1.5,
                                fontSize: '1rem',
                                backgroundColor: '#3b82f6',
                                '&:hover': {
                                    backgroundColor: '#2563eb',
                                },
                                '&:disabled': {
                                    backgroundColor: '#334155',
                                    color: '#94a3b8',
                                },
                            }}
                        >
                                {loading ? 'Signing in...' : 'Sign In'}
                            </Button>

                            <Box sx={{ mt: 2, textAlign: 'center' }}>
                                <Typography
                                    variant="body2"
                                    sx={{ color: '#64748b', mb: 1 }}
                                >
                                    Don't have an access key?
                                </Typography>
                                <Button
                                    variant="outlined"
                                    onClick={switchToRegister}
                                    startIcon={<PersonAddIcon />}
                                    sx={{
                                        borderColor: '#475569',
                                        color: '#94a3b8',
                                        '&:hover': {
                                            borderColor: '#3b82f6',
                                            color: '#3b82f6',
                                            backgroundColor: 'rgba(59, 130, 246, 0.1)',
                                        },
                                    }}
                                >
                                    Register New Key
                                </Button>
                            </Box>
                        </Box>
                    ) : (
                        // REGISTER VIEW
                        <Box
                            sx={{
                                width: '100%',
                                display: 'flex',
                                flexDirection: 'column',
                                gap: 2,
                            }}
                        >
                            {!registerSuccess ? (
                                <>
                                    <Typography
                                        variant="body2"
                                        sx={{
                                            color: '#94a3b8',
                                            textAlign: 'center',
                                            mb: 1,
                                        }}
                                    >
                                        Your unique access key has been generated. Copy and save it somewhere safe - you'll need it to sign in.
                                    </Typography>

                                    <TextField
                                        label="Your Access Key"
                                        value={generatedKey}
                                        fullWidth
                                        InputProps={{
                                            readOnly: true,
                                            endAdornment: (
                                                <InputAdornment position="end">
                                                    <Tooltip 
                                                        title={copied ? "Copied!" : "Copy to clipboard"}
                                                        TransitionComponent={Fade}
                                                    >
                                                        <IconButton
                                                            onClick={handleCopyKey}
                                                            edge="end"
                                                            sx={{ color: copied ? '#22c55e' : '#94a3b8' }}
                                                        >
                                                            {copied ? <CheckIcon /> : <ContentCopyIcon />}
                                                        </IconButton>
                                                    </Tooltip>
                                                </InputAdornment>
                                            ),
                                        }}
                                        sx={{
                                            '& .MuiInputBase-input': {
                                                color: '#22c55e',
                                                fontFamily: 'monospace',
                                                fontSize: '1.1rem',
                                                letterSpacing: '2px',
                                                fontWeight: 600,
                                            },
                                            '& .MuiInputLabel-root': {
                                                color: '#94a3b8',
                                            },
                                            '& .MuiOutlinedInput-root': {
                                                backgroundColor: 'rgba(34, 197, 94, 0.05)',
                                                '& fieldset': {
                                                    borderColor: '#22c55e',
                                                },
                                                '&:hover fieldset': {
                                                    borderColor: '#22c55e',
                                                },
                                                '&.Mui-focused fieldset': {
                                                    borderColor: '#22c55e',
                                                },
                                            },
                                        }}
                                    />

                                    <Box
                                        sx={{
                                            display: 'flex',
                                            gap: 2,
                                            mt: 1,
                                        }}
                                    >
                                        <Button
                                            variant="outlined"
                                            onClick={handleGenerateKey}
                                            sx={{
                                                flex: 1,
                                                py: 1.5,
                                                borderColor: '#475569',
                                                color: '#94a3b8',
                                                '&:hover': {
                                                    borderColor: '#64748b',
                                                    backgroundColor: 'rgba(100, 116, 139, 0.1)',
                                                },
                                            }}
                                        >
                                            Regenerate
                                        </Button>
                                        <Button
                                            variant="contained"
                                            onClick={handleRegister}
                                            disabled={loading || !generatedKey}
                                            sx={{
                                                flex: 1,
                                                py: 1.5,
                                                backgroundColor: '#22c55e',
                                                '&:hover': {
                                                    backgroundColor: '#16a34a',
                                                },
                                                '&:disabled': {
                                                    backgroundColor: '#334155',
                                                    color: '#94a3b8',
                                                },
                                            }}
                                        >
                                            {loading ? 'Creating...' : 'Create Account'}
                                        </Button>
                                    </Box>

                                    <Box
                                        sx={{
                                            mt: 2,
                                            p: 2,
                                            backgroundColor: 'rgba(251, 191, 36, 0.1)',
                                            borderRadius: '8px',
                                            border: '1px solid rgba(251, 191, 36, 0.3)',
                                        }}
                                    >
                                        <Typography
                                            variant="body2"
                                            sx={{
                                                color: '#fbbf24',
                                                textAlign: 'center',
                                            }}
                                        >
                                            ⚠️ <strong>Important:</strong> Save this key securely! It cannot be recovered if lost.
                                        </Typography>
                                    </Box>
                                </>
                            ) : (
                                <>
                                    <Box
                                        sx={{
                                            p: 3,
                                            backgroundColor: 'rgba(34, 197, 94, 0.1)',
                                            borderRadius: '12px',
                                            border: '1px solid rgba(34, 197, 94, 0.3)',
                                            textAlign: 'center',
                                        }}
                                    >
                                        <CheckIcon sx={{ fontSize: 48, color: '#22c55e', mb: 1 }} />
                                        <Typography
                                            variant="h6"
                                            sx={{ color: '#22c55e', mb: 1 }}
                                        >
                                            Account Created Successfully!
                                        </Typography>
                                        <Typography
                                            variant="body2"
                                            sx={{ color: '#94a3b8' }}
                                        >
                                            Your access key is ready to use.
                                        </Typography>
                                    </Box>

                                    <TextField
                                        label="Your Access Key"
                                        value={generatedKey}
                                        fullWidth
                                        InputProps={{
                                            readOnly: true,
                                            endAdornment: (
                                                <InputAdornment position="end">
                                                    <Tooltip 
                                                        title={copied ? "Copied!" : "Copy to clipboard"}
                                                        TransitionComponent={Fade}
                                                    >
                                                        <IconButton
                                                            onClick={handleCopyKey}
                                                            edge="end"
                                                            sx={{ color: copied ? '#22c55e' : '#94a3b8' }}
                                                        >
                                                            {copied ? <CheckIcon /> : <ContentCopyIcon />}
                                                        </IconButton>
                                                    </Tooltip>
                                                </InputAdornment>
                                            ),
                                        }}
                                        sx={{
                                            '& .MuiInputBase-input': {
                                                color: '#22c55e',
                                                fontFamily: 'monospace',
                                                fontSize: '1.1rem',
                                                letterSpacing: '2px',
                                                fontWeight: 600,
                                            },
                                            '& .MuiInputLabel-root': {
                                                color: '#94a3b8',
                                            },
                                            '& .MuiOutlinedInput-root': {
                                                backgroundColor: 'rgba(34, 197, 94, 0.05)',
                                                '& fieldset': {
                                                    borderColor: '#22c55e',
                                                },
                                            },
                                        }}
                                    />

                                    <Button
                                        variant="contained"
                                        onClick={useGeneratedKeyToLogin}
                                        startIcon={<LoginIcon />}
                                        sx={{
                                            mt: 1,
                                            py: 1.5,
                                            fontSize: '1rem',
                                            backgroundColor: '#3b82f6',
                                            '&:hover': {
                                                backgroundColor: '#2563eb',
                                            },
                                        }}
                                    >
                                        Sign In Now
                                    </Button>
                                </>
                            )}

                            <Box sx={{ mt: 2, textAlign: 'center' }}>
                                <Button
                                    variant="text"
                                    onClick={switchToLogin}
                                    sx={{
                                        color: '#64748b',
                                        '&:hover': {
                                            color: '#94a3b8',
                                            backgroundColor: 'rgba(100, 116, 139, 0.1)',
                                        },
                                    }}
                                >
                                    ← Back to Sign In
                        </Button>
                    </Box>
                        </Box>
                    )}
                </Paper>
            </Container>
        </Box>
    );
}

export default Login;
