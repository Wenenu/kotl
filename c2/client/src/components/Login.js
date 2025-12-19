import React, { useState } from 'react';
import {
    Box,
    Paper,
    TextField,
    Button,
    Typography,
    Container,
} from '@mui/material';
import PersonIcon from '@mui/icons-material/Person';
import PersonAddIcon from '@mui/icons-material/PersonAdd';
import LoginIcon from '@mui/icons-material/Login';

function Login({ onLogin }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [registerUsername, setRegisterUsername] = useState('');
    const [registerPassword, setRegisterPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [isRegisterView, setIsRegisterView] = useState(false);
    const [registerSuccess, setRegisterSuccess] = useState(false);

    const handleLogin = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        if (!username || !password) {
            setError('Please enter your username and password');
            setLoading(false);
            return;
        }

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, password }),
                credentials: 'same-origin',
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ message: 'Server error' }));
                setError(errorData.message || `Server error: ${response.status}`);
                setLoading(false);
                return;
            }

            const data = await response.json();

            // Get location 
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

    const handleRegister = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        if (!registerUsername || !registerPassword || !confirmPassword) {
            setError('Please fill in all fields');
            setLoading(false);
            return;
        }

        if (registerUsername.length < 3) {
            setError('Username must be at least 3 characters long');
            setLoading(false);
            return;
        }

        if (registerPassword.length < 6) {
            setError('Password must be at least 6 characters long');
            setLoading(false);
            return;
        }

        if (registerPassword !== confirmPassword) {
            setError('Passwords do not match');
            setLoading(false);
            return;
        }

        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username: registerUsername, password: registerPassword }),
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

    const switchToRegister = () => {
        setIsRegisterView(true);
        setError('');
        setRegisterUsername('');
        setRegisterPassword('');
        setConfirmPassword('');
        setRegisterSuccess(false);
    };

    const switchToLogin = () => {
        setIsRegisterView(false);
        setError('');
        setRegisterUsername('');
        setRegisterPassword('');
        setConfirmPassword('');
        setRegisterSuccess(false);
    };

    const useRegisteredAccountToLogin = () => {
        setUsername(registerUsername);
        setPassword('');
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
                        <PersonIcon sx={{ fontSize: 32, color: '#fff' }} />
                    </Box>

                    <Typography
                        variant="h5"
                        sx={{
                            color: '#e0e7ff',
                            fontWeight: 600,
                            textAlign: 'center',
                        }}
                    >
                        {isRegisterView ? 'Create Account' : 'Sign In'}
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
                                label="Username"
                                type="text"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                            fullWidth
                            autoFocus
                                placeholder="Enter your username"
                            sx={{
                                '& .MuiInputBase-input': {
                                    color: '#e0e7ff',
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
                        <TextField
                                label="Password"
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                            fullWidth
                                placeholder="Enter your password"
                            sx={{
                                '& .MuiInputBase-input': {
                                    color: '#e0e7ff',
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
                                    Don't have an account?
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
                                    Create Account
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
                                    <Box
                                        component="form"
                                        onSubmit={handleRegister}
                                        sx={{
                                            width: '100%',
                                            display: 'flex',
                                            flexDirection: 'column',
                                            gap: 2,
                                        }}
                                    >
                                        <TextField
                                            label="Username"
                                            type="text"
                                            value={registerUsername}
                                            onChange={(e) => setRegisterUsername(e.target.value)}
                                            fullWidth
                                            autoFocus
                                            placeholder="Choose a username"
                                            sx={{
                                                '& .MuiInputBase-input': {
                                                    color: '#e0e7ff',
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
                                        <TextField
                                            label="Password"
                                            type="password"
                                            value={registerPassword}
                                            onChange={(e) => setRegisterPassword(e.target.value)}
                                            fullWidth
                                            placeholder="Choose a password (minimum of 6 characters)"
                                            sx={{
                                                '& .MuiInputBase-input': {
                                                    color: '#e0e7ff',
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
                                        <TextField
                                            label="Confirm Password"
                                            type="password"
                                            value={confirmPassword}
                                            onChange={(e) => setConfirmPassword(e.target.value)}
                                            fullWidth
                                            placeholder="Confirm your password"
                                            sx={{
                                                '& .MuiInputBase-input': {
                                                    color: '#e0e7ff',
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
                                            startIcon={<PersonAddIcon />}
                                            sx={{
                                                mt: 1,
                                                py: 1.5,
                                                fontSize: '1rem',
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
                                        <PersonAddIcon sx={{ fontSize: 48, color: '#22c55e', mb: 1 }} />
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
                                            Your account is ready to use.
                                        </Typography>
                                    </Box>

                                    <Button
                                        variant="contained"
                                        onClick={useRegisteredAccountToLogin}
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
