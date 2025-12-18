import React, { useState, useEffect } from 'react';
import {
    Box,
    Paper,
    Typography,
    Button,
    Grid,
    Chip,
    Divider,
    CircularProgress,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    Alert,
} from '@mui/material';
import {
    ShoppingCart as CartIcon,
    Check as CheckIcon,
    AccessTime as TimeIcon,
    OpenInNew as OpenIcon,
    Refresh as RefreshIcon,
} from '@mui/icons-material';

function PurchasePage() {
    const [themeColors, setThemeColors] = useState({
        primary: '#4ade80',
        secondary: '#60a5fa',
        background: '#1a1f2e',
        paper: '#252b3b',
        textPrimary: '#e2e8f0',
        textSecondary: '#94a3b8',
    });
    const [cryptoBotEnabled, setCryptoBotEnabled] = useState(false);
    const [loading, setLoading] = useState(false);
    const [paymentDialog, setPaymentDialog] = useState({ open: false, payUrl: '', invoiceId: null, plan: '' });
    const [checkingPayment, setCheckingPayment] = useState(false);
    const [paymentStatus, setPaymentStatus] = useState(null);
    const [error, setError] = useState('');

    useEffect(() => {
        const savedSettings = localStorage.getItem('themeSettings');
        if (savedSettings) {
            try {
                const parsed = JSON.parse(savedSettings);
                setThemeColors(prev => ({
                    ...prev,
                    primary: parsed.primary || prev.primary,
                    secondary: parsed.secondary || prev.secondary,
                    background: parsed.background || prev.background,
                    paper: parsed.paper || prev.paper,
                    textPrimary: parsed.textPrimary || prev.textPrimary,
                    textSecondary: parsed.textSecondary || prev.textSecondary,
                }));
            } catch (e) {
                console.error('Error loading theme settings:', e);
            }
        }
        
        // Check if CryptoBot is enabled
        checkCryptoBotStatus();
    }, []);

    const checkCryptoBotStatus = async () => {
        try {
            const response = await fetch('/api/payment/plans');
            if (response.ok) {
                const data = await response.json();
                setCryptoBotEnabled(data.cryptoBotEnabled);
            }
        } catch (err) {
            console.error('Error checking payment status:', err);
        }
    };

    const plans = [
        {
            id: 'week',
            name: 'WEEK',
            price: 20,
            duration: '7 days',
            features: [
                'Full payload builder access',
                'Unlimited payload generation',
                'All data collection features',
                'Log viewing & management',
            ],
            popular: false,
        },
        {
            id: 'month',
            name: 'MONTH',
            price: 55,
            duration: '30 days',
            features: [
                'Full payload builder access',
                'Unlimited payload generation',
                'All data collection features',
                'Log viewing & management',
                'Priority support',
            ],
            popular: true,
            savings: '31% savings vs weekly',
        },
        {
            id: '6month',
            name: '6 MONTH',
            price: 220,
            duration: '180 days',
            features: [
                'Full payload builder access',
                'Unlimited payload generation',
                'All data collection features',
                'Log viewing & management',
                'Priority support',
                'Best value',
            ],
            popular: false,
            savings: '54% savings vs weekly',
        },
    ];

    const handlePurchase = async (plan) => {
        if (!cryptoBotEnabled) {
            alert(`To purchase the ${plan.name} plan (€${plan.price}), please contact the administrator.`);
            return;
        }
        
        setLoading(true);
        setError('');
        
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/payment/create-invoice', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ planId: plan.id })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || 'Failed to create invoice');
            }
            
            // Open payment dialog
            setPaymentDialog({
                open: true,
                payUrl: data.payUrl,
                invoiceId: data.invoiceId,
                plan: plan.name,
                amount: data.amount,
                currency: data.currency
            });
            setPaymentStatus(null);
            
        } catch (err) {
            console.error('Error creating invoice:', err);
            setError(err.message || 'Failed to create payment invoice');
        } finally {
            setLoading(false);
        }
    };

    const handleOpenPayment = () => {
        if (paymentDialog.payUrl) {
            window.open(paymentDialog.payUrl, '_blank');
        }
    };

    const handleCheckPayment = async () => {
        if (!paymentDialog.invoiceId) return;
        
        setCheckingPayment(true);
        
        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch(`/api/payment/check/${paymentDialog.invoiceId}`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });
            
            const data = await response.json();
            
            if (data.paid) {
                setPaymentStatus('paid');
            } else {
                setPaymentStatus(data.status || 'pending');
            }
            
        } catch (err) {
            console.error('Error checking payment:', err);
        } finally {
            setCheckingPayment(false);
        }
    };

    const handleCloseDialog = () => {
        setPaymentDialog({ open: false, payUrl: '', invoiceId: null, plan: '' });
        setPaymentStatus(null);
        
        // Reload page if payment was successful to refresh subscription status
        if (paymentStatus === 'paid') {
            window.location.reload();
        }
    };

    return (
        <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
            <Box sx={{ textAlign: 'center', mb: 5 }}>
                <Typography 
                    variant="h4" 
                    sx={{ 
                        color: themeColors.primary, 
                        fontWeight: 700,
                        mb: 2,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: 2
                    }}
                >
                    <CartIcon sx={{ fontSize: 36 }} />
                    Purchase Subscription
                </Typography>
                <Typography variant="body1" sx={{ color: themeColors.textSecondary, maxWidth: 600, mx: 'auto' }}>
                    Get access to the payload builder and start collecting data. Choose the plan that works best for you.
                </Typography>
                {cryptoBotEnabled && (
                    <Chip 
                        label="💎 Pay with Crypto (BTC, ETH, USDT, TON)" 
                        sx={{ 
                            mt: 2, 
                            backgroundColor: `${themeColors.primary}20`,
                            color: themeColors.primary,
                            fontWeight: 600
                        }} 
                    />
                )}
            </Box>

            {error && (
                <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError('')}>
                    {error}
                </Alert>
            )}

            <Grid container spacing={3} justifyContent="center">
                {plans.map((plan) => (
                    <Grid item xs={12} sm={6} md={4} key={plan.id}>
                        <Paper
                            sx={{
                                p: 0,
                                height: '100%',
                                display: 'flex',
                                flexDirection: 'column',
                                position: 'relative',
                                overflow: 'hidden',
                                border: plan.popular 
                                    ? `2px solid ${themeColors.primary}` 
                                    : `1px solid ${themeColors.textSecondary}33`,
                                backgroundColor: themeColors.paper,
                                transition: 'transform 0.2s, box-shadow 0.2s',
                                '&:hover': {
                                    transform: 'translateY(-4px)',
                                    boxShadow: `0 12px 40px ${themeColors.primary}20`,
                                },
                            }}
                        >
                            {/* Popular Badge */}
                            {plan.popular && (
                                <Box
                                    sx={{
                                        position: 'absolute',
                                        top: 16,
                                        right: -32,
                                        backgroundColor: themeColors.primary,
                                        color: themeColors.background,
                                        px: 4,
                                        py: 0.5,
                                        transform: 'rotate(45deg)',
                                        fontSize: '0.7rem',
                                        fontWeight: 700,
                                    }}
                                >
                                    POPULAR
                                </Box>
                            )}

                            {/* Header */}
                            <Box 
                                sx={{ 
                                    p: 3, 
                                    textAlign: 'center',
                                    backgroundColor: plan.popular 
                                        ? `${themeColors.primary}15` 
                                        : 'transparent',
                                }}
                            >
                                <Typography 
                                    variant="h6" 
                                    sx={{ 
                                        color: themeColors.textSecondary,
                                        fontWeight: 600,
                                        letterSpacing: 2,
                                        mb: 1,
                                    }}
                                >
                                    {plan.name}
                                </Typography>
                                
                                <Box sx={{ display: 'flex', alignItems: 'baseline', justifyContent: 'center', gap: 0.5 }}>
                                    <Typography 
                                        variant="h3" 
                                        sx={{ 
                                            color: themeColors.textPrimary,
                                            fontWeight: 700,
                                        }}
                                    >
                                        €{plan.price}
                                    </Typography>
                                </Box>
                                
                                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 0.5, mt: 1 }}>
                                    <TimeIcon sx={{ fontSize: 16, color: themeColors.textSecondary }} />
                                    <Typography variant="body2" sx={{ color: themeColors.textSecondary }}>
                                        {plan.duration}
                                    </Typography>
                                </Box>

                                {plan.savings && (
                                    <Chip
                                        label={plan.savings}
                                        size="small"
                                        sx={{
                                            mt: 1.5,
                                            backgroundColor: `${themeColors.primary}20`,
                                            color: themeColors.primary,
                                            fontWeight: 600,
                                            fontSize: '0.7rem',
                                        }}
                                    />
                                )}
                            </Box>

                            <Divider sx={{ borderColor: `${themeColors.textSecondary}33` }} />

                            {/* Features */}
                            <Box sx={{ p: 3, flexGrow: 1 }}>
                                {plan.features.map((feature, index) => (
                                    <Box 
                                        key={index}
                                        sx={{ 
                                            display: 'flex', 
                                            alignItems: 'center', 
                                            gap: 1.5,
                                            mb: 1.5,
                                        }}
                                    >
                                        <CheckIcon 
                                            sx={{ 
                                                fontSize: 18, 
                                                color: themeColors.primary,
                                            }} 
                                        />
                                        <Typography 
                                            variant="body2" 
                                            sx={{ color: themeColors.textSecondary }}
                                        >
                                            {feature}
                                        </Typography>
                                    </Box>
                                ))}
                            </Box>

                            {/* CTA Button */}
                            <Box sx={{ p: 3, pt: 0 }}>
                                <Button
                                    variant={plan.popular ? 'contained' : 'outlined'}
                                    fullWidth
                                    size="large"
                                    onClick={() => handlePurchase(plan)}
                                    disabled={loading}
                                    sx={{
                                        py: 1.5,
                                        fontWeight: 600,
                                        ...(plan.popular ? {
                                            backgroundColor: themeColors.primary,
                                            color: themeColors.background,
                                            '&:hover': {
                                                backgroundColor: themeColors.primary,
                                                filter: 'brightness(1.1)',
                                            },
                                        } : {
                                            borderColor: themeColors.textSecondary,
                                            color: themeColors.textPrimary,
                                            '&:hover': {
                                                borderColor: themeColors.primary,
                                                backgroundColor: `${themeColors.primary}10`,
                                            },
                                        }),
                                    }}
                                >
                                    {loading ? <CircularProgress size={24} /> : `Purchase ${plan.name}`}
                                </Button>
                            </Box>
                        </Paper>
                    </Grid>
                ))}
            </Grid>

            {/* Footer Info */}
            <Box sx={{ mt: 5, textAlign: 'center' }}>
                <Paper 
                    sx={{ 
                        p: 3, 
                        backgroundColor: `${themeColors.primary}10`,
                        border: `1px solid ${themeColors.primary}33`,
                    }}
                >
                    <Typography variant="body2" sx={{ color: themeColors.textSecondary, mb: 1 }}>
                        <strong style={{ color: themeColors.primary }}>
                            {cryptoBotEnabled ? '💎 Crypto Payments Enabled' : 'How to purchase:'}
                        </strong>
                    </Typography>
                    <Typography variant="body2" sx={{ color: themeColors.textSecondary }}>
                        {cryptoBotEnabled 
                            ? 'Click on a plan to generate a payment invoice. Pay with Bitcoin, Ethereum, USDT, TON, or other cryptocurrencies. Your subscription will be activated automatically after payment confirmation.'
                            : 'Contact the administrator with your preferred plan and access key. Once payment is confirmed, your subscription will be activated immediately.'
                        }
                    </Typography>
                </Paper>
            </Box>

            {/* Payment Dialog */}
            <Dialog 
                open={paymentDialog.open} 
                onClose={handleCloseDialog}
                maxWidth="sm"
                fullWidth
                PaperProps={{
                    sx: {
                        backgroundColor: themeColors.paper,
                        border: `1px solid ${themeColors.textSecondary}33`,
                    }
                }}
            >
                <DialogTitle sx={{ color: themeColors.textPrimary, textAlign: 'center' }}>
                    💎 Complete Your Payment
                </DialogTitle>
                <DialogContent>
                    <Box sx={{ textAlign: 'center', py: 2 }}>
                        <Typography variant="h5" sx={{ color: themeColors.primary, fontWeight: 700, mb: 1 }}>
                            {paymentDialog.plan} Subscription
                        </Typography>
                        <Typography variant="h4" sx={{ color: themeColors.textPrimary, mb: 3 }}>
                            €{paymentDialog.amount}
                        </Typography>
                        
                        {paymentStatus === 'paid' ? (
                            <Alert severity="success" sx={{ mb: 2 }}>
                                <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                                    ✓ Payment Confirmed!
                                </Typography>
                                <Typography variant="body2">
                                    Your subscription has been activated. Refresh the page to see your updated status.
                                </Typography>
                            </Alert>
                        ) : (
                            <>
                                <Typography variant="body2" sx={{ color: themeColors.textSecondary, mb: 3 }}>
                                    Click the button below to open the payment page. You can pay with BTC, ETH, USDT, TON, and other cryptocurrencies.
                                </Typography>
                                
                                <Button
                                    variant="contained"
                                    size="large"
                                    startIcon={<OpenIcon />}
                                    onClick={handleOpenPayment}
                                    sx={{
                                        backgroundColor: '#0088cc',
                                        color: '#fff',
                                        py: 1.5,
                                        px: 4,
                                        mb: 2,
                                        '&:hover': {
                                            backgroundColor: '#006699',
                                        }
                                    }}
                                >
                                    Open CryptoBot Payment
                                </Button>
                                
                                <Box sx={{ mt: 2 }}>
                                    <Button
                                        variant="outlined"
                                        startIcon={checkingPayment ? <CircularProgress size={16} /> : <RefreshIcon />}
                                        onClick={handleCheckPayment}
                                        disabled={checkingPayment}
                                        sx={{
                                            borderColor: themeColors.textSecondary,
                                            color: themeColors.textSecondary,
                                        }}
                                    >
                                        {checkingPayment ? 'Checking...' : 'Check Payment Status'}
                                    </Button>
                                    
                                    {paymentStatus && paymentStatus !== 'paid' && (
                                        <Typography variant="body2" sx={{ color: themeColors.textSecondary, mt: 1 }}>
                                            Status: {paymentStatus}
                                        </Typography>
                                    )}
                                </Box>
                            </>
                        )}
                    </Box>
                </DialogContent>
                <DialogActions sx={{ justifyContent: 'center', pb: 3 }}>
                    <Button onClick={handleCloseDialog} sx={{ color: themeColors.textSecondary }}>
                        {paymentStatus === 'paid' ? 'Close & Refresh' : 'Close'}
                    </Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
}

export default PurchasePage;
