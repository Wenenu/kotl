import React, { useState } from 'react';
import {
    Box,
    Paper,
    TextField,
    Button,
    Typography,
    Container,
} from '@mui/material';

function Login({ onLogin }) {
    const [password, setPassword] = useState('');
    const [username, setUsername] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        if (!username || !password) {
            setError('Please enter both username and password');
            setLoading(false);
            return;
        }

        try {
            // Authenticate with backend
            // In development, proxy in package.json should route /api/* to localhost:3001
            // In production, the backend serves the React app, so /api/* works directly
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
                username: username,
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
                    {error && (
                        <Typography
                            variant="body2"
                            sx={{
                                color: '#ef4444',
                                mb: 2,
                                textAlign: 'center',
                            }}
                        >
                            {error}
                        </Typography>
                    )}
                    <Box
                        component="form"
                        onSubmit={handleSubmit}
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
                            sx={{
                                '& .MuiInputBase-input': {
                                    color: '#e0e7ff',
                                },
                                '& .MuiInputLabel-root': {
                                    color: '#94a3b8',
                                },
                            }}
                        />
                        <TextField
                            label="Password"
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            fullWidth
                            sx={{
                                '& .MuiInputBase-input': {
                                    color: '#e0e7ff',
                                },
                                '& .MuiInputLabel-root': {
                                    color: '#94a3b8',
                                },
                            }}
                        />
                        <Button
                            type="submit"
                            variant="contained"
                            fullWidth
                            disabled={loading}
                            sx={{
                                mt: 2,
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
                            {loading ? 'Logging in...' : 'Log In'}
                        </Button>
                    </Box>
                </Paper>
            </Container>
        </Box>
    );
}

export default Login;
