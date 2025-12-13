import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Paper,
    TableSortLabel,
    TextField,
    Box,
    TablePagination,
    Button,
    Toolbar,
    Typography,
    CircularProgress,
    Checkbox,
} from '@mui/material';
import { visuallyHidden } from '@mui/utils';

const headCells = [
    { id: 'ip', numeric: false, disablePadding: false, label: 'IP' },
    { id: 'country', numeric: false, disablePadding: false, label: 'Country' },
    { id: 'date', numeric: false, disablePadding: false, label: 'Date' },
    { id: 'dataSummary', numeric: false, disablePadding: false, label: 'Data Summary' },
    { id: 'actions', numeric: false, disablePadding: false, label: 'Actions' },
];

function LogsTable() {
    const [logs, setLogs] = useState([]);
    const [error, setError] = useState(null);
    const [filterIp, setFilterIp] = useState('');
    const [filterCountry, setFilterCountry] = useState('');
    const [sortKey, setSortKey] = useState('date');
    const [sortDirection, setSortDirection] = useState('desc');
    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(10);
    const [selected, setSelected] = useState([]);

    const navigate = useNavigate();

    const fetchLogs = useCallback(async () => {
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/logs', {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            if (!response.ok) {
                throw new Error(`Server responded with status: ${response.status} - ${await response.text()}`);
            }
            const jsonData = await response.json();
            setLogs(jsonData);
            setError(null);
        } catch (err) {
            console.error("Failed to fetch logs:", err);
            setError(`Error fetching logs: ${err.message}`);
        }
    }, []);

    useEffect(() => {
        fetchLogs();
        const intervalId = setInterval(fetchLogs, 3000);
        return () => clearInterval(intervalId);
    }, [fetchLogs]);

    // Clear selection when filters change
    useEffect(() => {
        setSelected([]);
    }, [filterIp, filterCountry]);

    const handleSort = (property) => {
        const isAsc = sortKey === property && sortDirection === 'asc';
        setSortDirection(isAsc ? 'desc' : 'asc');
        setSortKey(property);
    };

    const handleViewLogDetails = (logId) => {
        navigate(`/log/${logId}`);
    };
    
    const handleDownload = async (logId) => {
        try {
            const response = await fetch(`/api/download/${logId}`);
            if (response.ok) {
                const blob = await response.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = `${logId}_data.zip`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                alert('Download started successfully!');
            } else {
                alert(`Error: ${response.status} - ${await response.text()}`);
            }
        } catch (err) {
            console.error("Download failed:", err);
            alert("Failed to start download.");
        }
    };

    const handleChangePage = (event, newPage) => {
        setPage(newPage);
        setSelected([]); // Clear selection when changing pages
    };

    const handleChangeRowsPerPage = (event) => {
        setRowsPerPage(parseInt(event.target.value, 10));
        setPage(0);
    };

    const filteredLogs = logs.filter(log => {
        const ipMatch = filterIp === '' || log.ip.toLowerCase().includes(filterIp.toLowerCase());
        const countryMatch = filterCountry === '' || log.country.toLowerCase().includes(filterCountry.toLowerCase());
        return ipMatch && countryMatch;
    });

    const sortedLogs = [...filteredLogs].sort((a, b) => {
        const aValue = a[sortKey];
        const bValue = b[sortKey];

        if (bValue < aValue) {
            return sortDirection === 'desc' ? -1 : 1;
        }
        if (bValue > aValue) {
            return sortDirection === 'desc' ? 1 : -1;
        }
        return 0;
    });

    const handleSelectAllClick = (event) => {
        if (event.target.checked) {
            const newSelected = sortedLogs.map((log) => log.id);
            setSelected(newSelected);
            return;
        }
        setSelected([]);
    };

    const handleSelectClick = (event, logId) => {
        const selectedIndex = selected.indexOf(logId);
        let newSelected = [];

        if (selectedIndex === -1) {
            newSelected = newSelected.concat(selected, logId);
        } else if (selectedIndex === 0) {
            newSelected = newSelected.concat(selected.slice(1));
        } else if (selectedIndex === selected.length - 1) {
            newSelected = newSelected.concat(selected.slice(0, -1));
        } else if (selectedIndex > 0) {
            newSelected = newSelected.concat(
                selected.slice(0, selectedIndex),
                selected.slice(selectedIndex + 1),
            );
        }

        setSelected(newSelected);
    };

    const isSelected = (logId) => selected.indexOf(logId) !== -1;

    const handleDeleteSelected = async () => {
        if (selected.length === 0) return;

        if (!window.confirm(`Are you sure you want to delete ${selected.length} log(s)?`)) {
            return;
        }

        try {
            const response = await fetch('/api/logs/delete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ logIds: selected }),
            });

            if (response.ok) {
                setSelected([]);
                fetchLogs(); // Refresh the logs list
            } else {
                alert(`Error deleting logs: ${response.statusText}`);
            }
        } catch (err) {
            console.error("Delete failed:", err);
            alert("Failed to delete logs.");
        }
    };

    if (error) return (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
            <Typography color="error">{error}</Typography>
        </Box>
    );

    return (
        <Paper sx={{ width: '100%', mb: 2, backgroundColor: '#252b3b', border: '1px solid #334155', borderRadius: '12px', overflow: 'hidden' }}>
            <Toolbar>
                <Typography sx={{ flex: '1 1 100%', variant: 'h6', component: 'div', color: '#4ade80', fontWeight: 600 }}>
                    Client Logs
                </Typography>
                <TextField
                    label="Filter by IP"
                    variant="outlined"
                    size="small"
                    value={filterIp}
                    onChange={(e) => setFilterIp(e.target.value)}
                    sx={{ mr: 2 }}
                />
                <TextField
                    label="Filter by Country"
                    variant="outlined"
                    size="small"
                    value={filterCountry}
                    onChange={(e) => setFilterCountry(e.target.value)}
                    sx={{ mr: 2 }}
                />
                <Button 
                    variant="contained" 
                    color="error" 
                    onClick={handleDeleteSelected}
                    disabled={selected.length === 0}
                    sx={{
                        borderRadius: '8px',
                    }}
                >
                    Delete Selected ({selected.length})
                </Button>
            </Toolbar>
            <TableContainer>
                {logs.length === 0 ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                        <CircularProgress sx={{ color: '#4ade80' }} />
                        <Typography sx={{ ml: 2, color: '#94a3b8' }}>Waiting for client logs...</Typography>
                    </Box>
                ) : (
                    <Table sx={{ minWidth: 750 }} aria-labelledby="tableTitle">
                        <TableHead>
                            <TableRow>
                                <TableCell padding="checkbox">
                                    <Checkbox
                                        color="primary"
                                        indeterminate={selected.length > 0 && selected.length < sortedLogs.length}
                                        checked={sortedLogs.length > 0 && selected.length === sortedLogs.length}
                                        onChange={handleSelectAllClick}
                                        inputProps={{
                                            'aria-label': 'select all logs',
                                        }}
                                        sx={{
                                            color: '#4ade80',
                                            '&.Mui-checked': {
                                                color: '#4ade80',
                                            },
                                        }}
                                    />
                                </TableCell>
                                {headCells.map((headCell) => (
                                    <TableCell
                                        key={headCell.id}
                                        align={headCell.numeric ? 'right' : 'left'}
                                        padding={headCell.disablePadding ? 'none' : 'normal'}
                                        sortDirection={sortKey === headCell.id ? sortDirection : false}
                                        sx={{ color: '#4ade80', fontWeight: 600 }}
                                    >
                                        <TableSortLabel
                                            active={sortKey === headCell.id}
                                            direction={sortKey === headCell.id ? sortDirection : 'asc'}
                                            onClick={() => handleSort(headCell.id)}
                                            sx={{
                                                color: '#4ade80',
                                                '&:hover': {
                                                    color: '#22c55e',
                                                },
                                                '&.Mui-active': {
                                                    color: '#4ade80',
                                                },
                                                '& .MuiTableSortLabel-icon': {
                                                    color: '#4ade80 !important',
                                                },
                                            }}
                                        >
                                            {headCell.label}
                                            {sortKey === headCell.id ? (
                                                <Box component="span" sx={visuallyHidden}>
                                                    {sortDirection === 'desc' ? 'sorted descending' : 'sorted ascending'}
                                                </Box>
                                            ) : null}
                                        </TableSortLabel>
                                    </TableCell>
                                ))}
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {sortedLogs.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage).map((log, index) => {
                                const isItemSelected = isSelected(log.id);
                                const labelId = `enhanced-table-checkbox-${index}`;

                                return (
                                    <TableRow
                                        hover
                                        onClick={(event) => handleSelectClick(event, log.id)}
                                        role="checkbox"
                                        aria-checked={isItemSelected}
                                        tabIndex={-1}
                                        key={log.id}
                                        selected={isItemSelected}
                                        sx={{
                                            '&:hover': {
                                                backgroundColor: 'rgba(255, 255, 255, 0.03)',
                                            },
                                            '&.Mui-selected': {
                                                backgroundColor: 'rgba(74, 222, 128, 0.1)',
                                                '&:hover': {
                                                    backgroundColor: 'rgba(74, 222, 128, 0.15)',
                                                },
                                            }
                                        }}
                                    >
                                        <TableCell padding="checkbox">
                                            <Checkbox
                                                color="primary"
                                                checked={isItemSelected}
                                                inputProps={{
                                                    'aria-labelledby': labelId,
                                                }}
                                                onClick={(e) => e.stopPropagation()}
                                                sx={{
                                                    color: '#4ade80',
                                                    '&.Mui-checked': {
                                                        color: '#4ade80',
                                                    },
                                                }}
                                            />
                                        </TableCell>
                                        <TableCell component="th" id={labelId} scope="row" sx={{ color: '#e2e8f0' }}>
                                            {log.ip}
                                        </TableCell>
                                        <TableCell sx={{ color: '#94a3b8' }}>{log.country}</TableCell>
                                        <TableCell sx={{ color: '#94a3b8' }}>{new Date(log.date).toLocaleString()}</TableCell>
                                        <TableCell sx={{ color: '#94a3b8' }}>
                                            {`H:${log.dataSummary.historyEntries || 0}, P:${log.dataSummary.processes || 0}, A:${log.dataSummary.installedApps || 0}, C:${log.dataSummary.cookies || 0}`}
                                        </TableCell>
                                        <TableCell>
                                            <Button 
                                                variant="contained" 
                                                onClick={() => handleViewLogDetails(log.id)} 
                                                sx={{ 
                                                    mr: 1,
                                                    backgroundColor: '#4ade80',
                                                    color: '#1a1f2e',
                                                    borderRadius: '8px',
                                                    '&:hover': {
                                                        backgroundColor: '#22c55e',
                                                    }
                                                }}
                                            >
                                                View
                                            </Button>
                                            <Button 
                                                variant="outlined" 
                                                onClick={() => handleDownload(log.id)}
                                                sx={{
                                                    borderColor: '#334155',
                                                    color: '#e2e8f0',
                                                    borderRadius: '8px',
                                                    '&:hover': {
                                                        borderColor: '#4ade80',
                                                        backgroundColor: 'rgba(74, 222, 128, 0.1)',
                                                    }
                                                }}
                                            >
                                                Download
                                            </Button>
                                        </TableCell>
                                    </TableRow>
                                );
                            })}
                        </TableBody>
                    </Table>
                )}
            </TableContainer>
            <TablePagination
                rowsPerPageOptions={[5, 10, 25]}
                component="div"
                count={filteredLogs.length}
                rowsPerPage={rowsPerPage}
                page={page}
                onPageChange={handleChangePage}
                onRowsPerPageChange={handleChangeRowsPerPage}
            />
        </Paper>
    );
}

export default LogsTable;
