import { createTheme } from '@mui/material/styles';

// Helper functions for color manipulation
function hexToRgb(hex) {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result ? {
    r: parseInt(result[1], 16),
    g: parseInt(result[2], 16),
    b: parseInt(result[3], 16)
  } : null;
}

function rgbToHex(r, g, b) {
  return "#" + [r, g, b].map(x => {
    const hex = x.toString(16);
    return hex.length === 1 ? "0" + hex : hex;
  }).join("");
}

function lightenColor(hex, percent) {
  const rgb = hexToRgb(hex);
  if (!rgb) return hex;
  const r = Math.min(255, Math.floor(rgb.r + (255 - rgb.r) * percent));
  const g = Math.min(255, Math.floor(rgb.g + (255 - rgb.g) * percent));
  const b = Math.min(255, Math.floor(rgb.b + (255 - rgb.b) * percent));
  return rgbToHex(r, g, b);
}

function darkenColor(hex, percent) {
  const rgb = hexToRgb(hex);
  if (!rgb) return hex;
  const r = Math.max(0, Math.floor(rgb.r * (1 - percent)));
  const g = Math.max(0, Math.floor(rgb.g * (1 - percent)));
  const b = Math.max(0, Math.floor(rgb.b * (1 - percent)));
  return rgbToHex(r, g, b);
}

function adjustOpacity(hex, opacity) {
  const rgb = hexToRgb(hex);
  if (!rgb) return hex;
  return `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${opacity})`;
}

function isLightColor(hex) {
  const rgb = hexToRgb(hex);
  if (!rgb) return false;
  // Calculate relative luminance
  const luminance = (0.299 * rgb.r + 0.587 * rgb.g + 0.114 * rgb.b) / 255;
  return luminance > 0.5;
}

export const createCustomTheme = (settings = {}) => {
  const {
    primary = '#4ade80',
    secondary = '#60a5fa',
    background = '#1a1f2e',
    paper = '#252b3b',
    textPrimary = '#e2e8f0',
    textSecondary = '#94a3b8',
    borderRadius = 12,
    fontFamily = 'Inter',
  } = settings;

  return createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: primary,
      light: lightenColor(primary, 0.2),
      dark: darkenColor(primary, 0.2),
    },
    secondary: {
      main: secondary,
      light: lightenColor(secondary, 0.2),
      dark: darkenColor(secondary, 0.2),
    },
    background: {
      default: background,
      paper: paper,
    },
    text: {
      primary: textPrimary,
      secondary: textSecondary,
    },
    divider: '#334155', // Softer divider color
  },
  typography: {
    fontFamily: [
      fontFamily,
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
      color: textPrimary,
    },
    h5: {
      fontWeight: 600,
      fontSize: '1.5rem',
      color: textPrimary,
    },
    h6: {
      fontWeight: 600,
      fontSize: '1.25rem',
      color: textPrimary,
    },
    body1: {
      color: textPrimary,
    },
    body2: {
      color: textSecondary,
    },
  },
  components: {
    MuiAppBar: {
      styleOverrides: {
        root: {
          backgroundColor: background,
          borderBottom: `1px solid ${adjustOpacity(textSecondary, 0.3)}`,
          boxShadow: '0 2px 8px rgba(0, 0, 0, 0.3)',
          borderRadius: 0,
        },
      },
    },
    MuiDrawer: {
      styleOverrides: {
        paper: {
          backgroundColor: darkenColor(background, 0.05),
          borderRight: `1px solid ${adjustOpacity(textSecondary, 0.3)}`,
          color: textPrimary,
        },
      },
    },
    MuiListItemButton: {
      styleOverrides: {
        root: {
          color: textSecondary,
          borderRadius: `${borderRadius * 0.67}px`,
          margin: '4px 8px',
          '&.active': {
            backgroundColor: `${primary}26`,
            color: primary,
            borderLeft: `3px solid ${primary}`,
            '& .MuiListItemIcon-root': {
              color: primary,
            },
            '& .MuiListItemText-primary': {
              color: primary,
              fontWeight: 600,
            },
          },
          '&:hover': {
            backgroundColor: 'rgba(255, 255, 255, 0.05)',
            color: textPrimary,
          },
        },
      },
    },
    MuiListItemIcon: {
      styleOverrides: {
        root: {
          color: textSecondary,
          minWidth: '40px',
        },
      },
    },
    MuiListItemText: {
      styleOverrides: {
        primary: {
          color: textSecondary,
          fontSize: '0.95rem',
        },
      },
    },
    MuiPaper: {
      styleOverrides: {
        root: {
          backgroundColor: paper,
          backgroundImage: 'none',
          boxShadow: '0 4px 12px rgba(0, 0, 0, 0.3)',
          border: `1px solid ${adjustOpacity(textSecondary, 0.3)}`,
          borderRadius: `${borderRadius}px`,
        },
      },
    },
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 500,
          borderRadius: `${borderRadius * 0.67}px`,
        },
        contained: {
          backgroundColor: primary,
          color: isLightColor(primary) ? '#000' : '#fff',
          '&:hover': {
            backgroundColor: darkenColor(primary, 0.15),
          },
        },
        outlined: {
          borderColor: primary,
          color: primary,
          '&:hover': {
            borderColor: darkenColor(primary, 0.15),
            backgroundColor: `${primary}1A`,
          },
        },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: {
          backgroundColor: paper,
          color: textPrimary,
          border: `1px solid ${adjustOpacity(textSecondary, 0.3)}`,
          fontWeight: 500,
          borderRadius: `${borderRadius * 0.67}px`,
        },
        colorSuccess: {
          backgroundColor: `${primary}26`,
          color: primary,
          border: `1px solid ${adjustOpacity(primary, 0.3)}`,
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
          borderColor: adjustOpacity(textSecondary, 0.3),
          color: textPrimary,
        },
        head: {
          backgroundColor: paper,
          color: primary,
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
            backgroundColor: paper,
            color: textPrimary,
            borderRadius: `${borderRadius * 0.67}px`,
            '& fieldset': {
              borderColor: adjustOpacity(textSecondary, 0.3),
            },
            '&:hover fieldset': {
              borderColor: primary,
            },
            '&.Mui-focused fieldset': {
              borderColor: primary,
            },
            '& .MuiInputBase-input': {
              color: `${textPrimary} !important`,
            },
          },
          '& .MuiInputLabel-root': {
            color: textSecondary,
            '&.Mui-focused': {
              color: primary,
            },
          },
        },
      },
    },
    MuiAccordion: {
      styleOverrides: {
        root: {
          backgroundColor: paper,
          border: `1px solid ${adjustOpacity(textSecondary, 0.3)}`,
          borderRadius: `${borderRadius}px !important`,
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
          backgroundColor: paper,
          borderRadius: `${borderRadius}px`,
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
          backgroundColor: paper,
        },
      },
    },
  },
  });
};

// Default theme for backward compatibility
const ntsleuthTheme = createCustomTheme();

export default ntsleuthTheme;
