import React, { useState, useEffect } from 'react';
import {
    BrowserRouter as Router,
    Routes,
    Route
} from 'react-router-dom';
import { Box, Toolbar, ThemeProvider, CssBaseline } from '@mui/material'; // Import ThemeProvider and CssBaseline
import { createCustomTheme } from './theme'; // Import theme creator function
import './App.css';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import DashboardPage from './pages/DashboardPage';
import StatisticsPage from './pages/StatisticsPage';
import TimelinePage from './pages/TimelinePage';
import SettingsPage from './pages/SettingsPage';
import LogDetailPage from './pages/LogDetailPage';
import PayloadBuilderPage from './pages/PayloadBuilderPage';
import Login from './components/Login';


function App() {
    const [isLoggedIn, setIsLoggedIn] = useState(false);
    const [theme, setTheme] = useState(() => {
        // Load theme settings from localStorage on initial load
        const savedSettings = localStorage.getItem('themeSettings');
        if (savedSettings) {
            try {
                const parsed = JSON.parse(savedSettings);
                return createCustomTheme(parsed);
            } catch (e) {
                console.error('Error loading theme settings:', e);
            }
        }
        return createCustomTheme();
    });

    useEffect(() => {
        const verifyToken = async () => {
            const token = localStorage.getItem('authToken');
            if (!token) {
                setIsLoggedIn(false);
                return;
            }

            // Verify token by making a test request
            try {
                const response = await fetch('/api/logs', {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });

                if (response.status === 401 || response.status === 403) {
                    // Token is invalid - clear it
                    localStorage.removeItem('authToken');
                    localStorage.removeItem('userInfo');
                    setIsLoggedIn(false);
                } else {
                    // Token is valid
                    setIsLoggedIn(true);
                }
            } catch (err) {
                // Network error - assume token is valid for now
                // User will see error when trying to fetch data
                setIsLoggedIn(true);
            }
        };

        verifyToken();
    }, []);

    useEffect(() => {
        // Listen for theme updates from Settings page
        const handleThemeUpdate = () => {
            const savedSettings = localStorage.getItem('themeSettings');
            if (savedSettings) {
                try {
                    const parsed = JSON.parse(savedSettings);
                    setTheme(createCustomTheme(parsed));
                } catch (e) {
                    console.error('Error loading theme settings:', e);
                }
            }
        };

        window.addEventListener('themeUpdated', handleThemeUpdate);
        return () => {
            window.removeEventListener('themeUpdated', handleThemeUpdate);
        };
    }, []);

    const handleLogin = (token) => {
        // Token is already stored in localStorage by Login component
        setIsLoggedIn(true);
    };

    const handleLogout = () => {
        localStorage.removeItem('authToken');
        setIsLoggedIn(false);
    };

    if (!isLoggedIn) {
        return <Login onLogin={handleLogin} />;
    }

    return (
        <Router>
            <ThemeProvider theme={theme}>
                <CssBaseline /> {/* Optional: For consistent baseline styles */}
                <Box sx={{ display: 'flex' }}>
                    <Header onLogout={handleLogout} />
                    <Sidebar />
                    <Box component="main" sx={{ flexGrow: 1, p: 3 }}>
                        <Toolbar />
                        <Routes>
                            <Route path="/" element={<DashboardPage />} />
                            <Route path="/statistics" element={<StatisticsPage />} />
                            <Route path="/builder" element={<PayloadBuilderPage />} />
                            <Route path="/timeline" element={<TimelinePage />} />
                            <Route path="/settings" element={<SettingsPage />} />
                            <Route path="/log/:logId" element={<LogDetailPage />} />
                        </Routes>
                    </Box>
                </Box>
            </ThemeProvider>
        </Router>
    );
}

export default App;
