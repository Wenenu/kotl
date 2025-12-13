import React, { useState, useEffect } from 'react';
import {
    BrowserRouter as Router,
    Routes,
    Route
} from 'react-router-dom';
import { Box, Toolbar, ThemeProvider, CssBaseline } from '@mui/material'; // Import ThemeProvider and CssBaseline
import ntsleuthTheme from './theme'; // Import your custom theme
import './App.css';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import DashboardPage from './pages/DashboardPage';
import StatisticsPage from './pages/StatisticsPage';
import TimelinePage from './pages/TimelinePage';
import SettingsPage from './pages/SettingsPage';
import LogDetailPage from './pages/LogDetailPage';
import Login from './components/Login';


function App() {
    const [isLoggedIn, setIsLoggedIn] = useState(false);

    useEffect(() => {
        const token = localStorage.getItem('authToken');
        if (token) {
            setIsLoggedIn(true);
        }
    }, []);

    const handleLogin = () => {
        localStorage.setItem('authToken', 'true');
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
            <ThemeProvider theme={ntsleuthTheme}>
                <CssBaseline /> {/* Optional: For consistent baseline styles */}
                <Box sx={{ display: 'flex' }}>
                    <Header onLogout={handleLogout} />
                    <Sidebar />
                    <Box component="main" sx={{ flexGrow: 1, p: 3 }}>
                        <Toolbar />
                        <Routes>
                            <Route path="/" element={<DashboardPage />} />
                            <Route path="/statistics" element={<StatisticsPage />} />
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
