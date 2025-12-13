import { createTheme } from '@mui/material/styles';

const ntsleuthTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#4ade80', // Softer, mellow green
      light: '#86efac',
      dark: '#22c55e',
    },
    secondary: {
      main: '#60a5fa', // Softer blue accent
      light: '#93c5fd',
      dark: '#3b82f6',
    },
    background: {
      default: '#1a1f2e', // Dark blue-gray instead of pure black
      paper: '#252b3b', // Slightly lighter blue-gray for cards
    },
    text: {
      primary: '#e2e8f0', // Soft white/off-white
      secondary: '#94a3b8', // Mellow gray for secondary text
    },
    divider: '#334155', // Softer divider color
  },
  typography: {
    fontFamily: [
      'Inter',
      '-apple-system',
      'BlinkMacSystemFont',
      'Segoe UI',
      'Roboto',
      'Oxygen',
      'Ubuntu',
      'Cantarell',
      'sans-serif',
    ].join(','),
    h4: {
      fontWeight: 700,
      fontSize: '2rem',
      color: '#e2e8f0',
    },
    h5: {
      fontWeight: 600,
      fontSize: '1.5rem',
      color: '#e2e8f0',
    },
    h6: {
      fontWeight: 600,
      fontSize: '1.25rem',
      color: '#e2e8f0',
    },
    body1: {
      color: '#e2e8f0',
    },
    body2: {
      color: '#94a3b8',
    },
  },
  components: {
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: '#1a1f2e',
          borderBottom: '1px solid #334155',
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.3)',
          borderRadius: 0,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: '#1e293b',
          borderRight: '1px solid #334155',
          color: '#e2e8f0',
        },
      },
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          color: '#94a3b8',
          borderRadius: '8px',
          margin: '4px 8px',
          '&.active': {
            backgroundColor: 'rgba(74, 222, 128, 0.15)',
            color: '#4ade80',
            borderLeft: '3px solid #4ade80',
            '& .MuiListItemIcon-root': {
              color: '#4ade80',
            },
            '& .MuiListItemText-primary': {
              color: '#4ade80',
              fontWeight: 600,
            },
          },
          '&:hover': {
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            color: '#e2e8f0',
          },
        },
      },
    },
    MuiListItemIcon: {
      styleOverrides: {
        root: {
          color: '#94a3b8',
          minWidth: '40px',
        },
      },
    },
    MuiListItemText: {
      styleOverrides: {
        primary: {
          color: '#94a3b8',
          fontSize: '0.95rem',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundColor: '#252b3b',
          backgroundImage: 'none',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
          border: '1px solid #334155',
          borderRadius: '12px',
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 500,
          borderRadius: '8px',
        },
        contained: {
          backgroundColor: '#4ade80',
          color: '#1a1f2e',
          '&:hover': {
            backgroundColor: '#22c55e',
          },
        },
        outlined: {
          borderColor: '#4ade80',
          color: '#4ade80',
          '&:hover': {
            borderColor: '#22c55e',
            backgroundColor: 'rgba(74, 222, 128, 0.1)',
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          backgroundColor: '#252b3b',
          color: '#e2e8f0',
          border: '1px solid #334155',
          fontWeight: 500,
          borderRadius: '8px',
        },
        colorSuccess: {
          backgroundColor: 'rgba(74, 222, 128, 0.15)',
          color: '#4ade80',
          border: '1px solid rgba(74, 222, 128, 0.3)',
        },
        colorError: {
          backgroundColor: 'rgba(239, 68, 68, 0.15)',
          color: '#ef4444',
          border: '1px solid rgba(239, 68, 68, 0.3)',
        },
      },
    },
    MuiTableCell: {
      styleOverrides: {
        root: {
          borderColor: '#334155',
          color: '#e2e8f0',
        },
        head: {
          backgroundColor: '#252b3b',
          color: '#4ade80',
          fontWeight: 600,
        },
      },
    },
    MuiTableRow: {
      styleOverrides: {
        root: {
          '&:hover': {
            backgroundColor: 'rgba(255, 255, 255, 0.03)',
          },
        },
      },
    },
    MuiTextField: {
      styleOverrides: {
        root: {
          '& .MuiOutlinedInput-root': {
            backgroundColor: '#252b3b',
            color: '#e2e8f0',
            borderRadius: '8px',
            '& fieldset': {
              borderColor: '#334155',
            },
            '&:hover fieldset': {
              borderColor: '#4ade80',
            },
            '&.Mui-focused fieldset': {
              borderColor: '#4ade80',
            },
            '& .MuiInputBase-input': {
              color: '#e2e8f0 !important',
            },
          },
          '& .MuiInputLabel-root': {
            color: '#94a3b8',
            '&.Mui-focused': {
              color: '#4ade80',
            },
          },
        },
      },
    },
    MuiAccordion: {
      styleOverrides: {
        root: {
          backgroundColor: '#252b3b',
          border: '1px solid #334155',
          borderRadius: '12px !important',
          marginBottom: '12px',
          '&:before': {
            display: 'none',
          },
          '&.Mui-expanded': {
            margin: '0 0 12px 0',
          },
        },
      },
    },
    MuiAccordionSummary: {
      styleOverrides: {
        root: {
          backgroundColor: '#252b3b',
          borderRadius: '12px',
          padding: '0 16px',
          '&:hover': {
            backgroundColor: 'rgba(255, 255, 255, 0.03)',
          },
          '&.Mui-expanded': {
            borderBottomLeftRadius: 0,
            borderBottomRightRadius: 0,
          },
        },
      },
    },
    MuiAccordionDetails: {
      styleOverrides: {
        root: {
          padding: '16px',
          backgroundColor: '#252b3b',
        },
      },
    },
  },
});

export default ntsleuthTheme;
