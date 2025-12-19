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
    TextField,
    Select,
    MenuItem,
    FormControl,
    InputLabel,
    IconButton,
    Tooltip,
} from '@mui/material';
import {
    ShoppingCart as CartIcon,
    Check as CheckIcon,
    AccessTime as TimeIcon,
    OpenInNew as OpenIcon,
    Refresh as RefreshIcon,
    ContentCopy as CopyIcon,
    CheckCircle as CheckCircleIcon,
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
    const [manualPaymentsEnabled, setManualPaymentsEnabled] = useState(false);
    const [wallets, setWallets] = useState({});
    const [loading, setLoading] = useState(false);
    const [paymentDialog, setPaymentDialog] = useState({ open: false, payUrl: '', invoiceId: null, plan: '', paymentMethod: 'cryptobot' });
    const [checkingPayment, setCheckingPayment] = useState(false);
    const [paymentStatus, setPaymentStatus] = useState(null);
    const [error, setError] = useState('');
    const [selectedCrypto, setSelectedCrypto] = useState('BTC');
    const [transactionHash, setTransactionHash] = useState('');
    const [submittingPayment, setSubmittingPayment] = useState(false);
    const [copiedAddress, setCopiedAddress] = useState('');

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
                setManualPaymentsEnabled(data.manualPaymentsEnabled);
                setWallets(data.wallets || {});
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
        if (!cryptoBotEnabled && !manualPaymentsEnabled) {
            const userInfo = JSON.parse(localStorage.getItem('userInfo') || '{}');
            const accessKey = userInfo?.username || 'your access key';
            alert(`To purchase the ${plan.name} plan (€${plan.price}), please contact the administrator.\n\nProvide them with:\n- Your access key: ${accessKey}\n- Plan: ${plan.name} (${plan.duration})\n- Price: €${plan.price}\n\nYour subscription will be activated once payment is confirmed.`);
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
                payUrl: data.payUrl || '',
                invoiceId: data.invoiceId || null,
                plan: plan.name,
                amount: data.amount,
                currency: data.currency,
                paymentMethod: data.paymentMethod || 'cryptobot',
                planId: data.planId || plan.id,
                days: data.days || plan.duration
            });
            setPaymentStatus(null);
            setTransactionHash('');
            setSelectedCrypto('BTC');
            
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
        setPaymentDialog({ open: false, payUrl: '', invoiceId: null, plan: '', paymentMethod: 'cryptobot' });
        setPaymentStatus(null);
        setTransactionHash('');
        
        // Reload page if payment was successful to refresh subscription status
        if (paymentStatus === 'paid') {
            window.location.reload();
        }
    };

    const handleCopyAddress = (address, crypto) => {
        navigator.clipboard.writeText(address);
        setCopiedAddress(crypto);
        setTimeout(() => setCopiedAddress(''), 2000);
    };

    const handleSubmitPayment = async () => {
        if (!transactionHash.trim()) {
            setError('Please enter a transaction hash');
            return;
        }

        setSubmittingPayment(true);
        setError('');

        try {
            const token = localStorage.getItem('authToken');
            const response = await fetch('/api/payment/submit', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    planId: paymentDialog.planId,
                    cryptoCurrency: selectedCrypto,
                    transactionHash: transactionHash.trim()
                })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'Failed to submit payment');
            }

            setPaymentStatus('submitted');
            setTransactionHash('');
            
        } catch (err) {
            console.error('Error submitting payment:', err);
            setError(err.message || 'Failed to submit payment');
        } finally {
            setSubmittingPayment(false);
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
                {cryptoBotEnabled ? (
                    <Chip 
                        label="💎 Pay with Crypto (200+ cryptocurrencies via NOWPayments)" 
                        sx={{ 
                            mt: 2, 
                            backgroundColor: `${themeColors.primary}20`,
                            color: themeColors.primary,
                            fontWeight: 600
                        }} 
                    />
                ) : manualPaymentsEnabled ? (
                    <Chip 
                        label="💎 Manual Crypto Payments (BTC, ETH, USDT)" 
                        sx={{ 
                            mt: 2, 
                            backgroundColor: `${themeColors.primary}20`,
                            color: themeColors.primary,
                            fontWeight: 600
                        }} 
                    />
                ) : (
                    <Alert 
                        severity="info" 
                        sx={{ 
                            mt: 2, 
                            maxWidth: 600, 
                            mx: 'auto',
                            backgroundColor: `${themeColors.secondary}20`,
                            border: `1px solid ${themeColors.secondary}33`
                        }}
                    >
                        <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>
                            Manual Payment Required
                        </Typography>
                        <Typography variant="body2">
                            Crypto payments are not available. Please contact the administrator to purchase a subscription.
                        </Typography>
                    </Alert>
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
                                    {loading ? (
                                        <CircularProgress size={24} />
                                    ) : (cryptoBotEnabled || manualPaymentsEnabled) ? (
                                        `Purchase ${plan.name}`
                                    ) : (
                                        `Contact Admin - €${plan.price}`
                                    )}
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
                            ? 'Click on a plan to generate a payment invoice. Pay with Bitcoin, Ethereum, USDT, or any of 200+ cryptocurrencies via NOWPayments. Your subscription will be activated automatically after payment confirmation.'
                            : manualPaymentsEnabled
                            ? 'Click on a plan to see wallet addresses. Send crypto to the provided address and submit your transaction hash. Your subscription will be activated after admin verification.'
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
                    <Box sx={{ py: 2 }}>
                        <Box sx={{ textAlign: 'center', mb: 3 }}>
                            <Typography variant="h5" sx={{ color: themeColors.primary, fontWeight: 700, mb: 1 }}>
                                {paymentDialog.plan} Subscription
                            </Typography>
                            <Typography variant="h4" sx={{ color: themeColors.textPrimary, mb: 2 }}>
                                €{paymentDialog.amount}
                            </Typography>
                        </Box>
                        
                        {paymentStatus === 'paid' || paymentStatus === 'submitted' ? (
                            <Alert severity={paymentStatus === 'paid' ? 'success' : 'info'} sx={{ mb: 2 }}>
                                <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                                    {paymentStatus === 'paid' ? '✓ Payment Confirmed!' : '✓ Payment Submitted!'}
                                </Typography>
                                <Typography variant="body2">
                                    {paymentStatus === 'paid' 
                                        ? 'Your subscription has been activated. Refresh the page to see your updated status.'
                                        : 'Your payment has been submitted and is pending verification. Your subscription will be activated once an admin verifies your transaction.'}
                                </Typography>
                            </Alert>
                        ) : paymentDialog.paymentMethod === 'manual' ? (
                            <>
                                <Alert severity="info" sx={{ mb: 3 }}>
                                    <Typography variant="body2">
                                        Send <strong>€{paymentDialog.amount}</strong> worth of cryptocurrency to one of the addresses below, then submit your transaction hash.
                                    </Typography>
                                </Alert>

                                {/* Wallet Addresses */}
                                <Box sx={{ mb: 3 }}>
                                    <Typography variant="subtitle2" sx={{ color: themeColors.textPrimary, mb: 2, fontWeight: 600 }}>
                                        Wallet Addresses:
                                    </Typography>
                                    {Object.entries(paymentDialog.wallets || wallets).map(([crypto, address]) => {
                                        if (!address || address.trim() === '') return null;
                                        return (
                                            <Box key={crypto} sx={{ mb: 2, p: 2, backgroundColor: `${themeColors.primary}10`, borderRadius: 1 }}>
                                                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                                                    <Typography variant="body2" sx={{ fontWeight: 600, color: themeColors.primary }}>
                                                        {crypto}
                                                    </Typography>
                                                    <Tooltip title={copiedAddress === crypto ? 'Copied!' : 'Copy address'}>
                                                        <IconButton 
                                                            size="small" 
                                                            onClick={() => handleCopyAddress(address, crypto)}
                                                            sx={{ color: themeColors.textSecondary }}
                                                        >
                                                            {copiedAddress === crypto ? <CheckCircleIcon fontSize="small" /> : <CopyIcon fontSize="small" />}
                                                        </IconButton>
                                                    </Tooltip>
                                                </Box>
                                                <Typography 
                                                    variant="body2" 
                                                    sx={{ 
                                                        color: themeColors.textSecondary,
                                                        fontFamily: 'monospace',
                                                        fontSize: '0.85rem',
                                                        wordBreak: 'break-all'
                                                    }}
                                                >
                                                    {address}
                                                </Typography>
                                            </Box>
                                        );
                                    })}
                                </Box>

                                {/* Payment Form */}
                                <Box sx={{ mb: 2 }}>
                                    <FormControl fullWidth sx={{ mb: 2 }}>
                                        <InputLabel sx={{ color: themeColors.textSecondary }}>Cryptocurrency</InputLabel>
                                        <Select
                                            value={selectedCrypto}
                                            onChange={(e) => setSelectedCrypto(e.target.value)}
                                            sx={{
                                                color: themeColors.textPrimary,
                                                '& .MuiOutlinedInput-notchedOutline': {
                                                    borderColor: `${themeColors.textSecondary}33`,
                                                },
                                                '&:hover .MuiOutlinedInput-notchedOutline': {
                                                    borderColor: themeColors.primary,
                                                },
                                            }}
                                        >
                                            {Object.keys(paymentDialog.wallets || wallets).filter(crypto => {
                                                const walletAddrs = paymentDialog.wallets || wallets;
                                                return walletAddrs[crypto] && walletAddrs[crypto].trim() !== '';
                                            }).map(crypto => (
                                                <MenuItem key={crypto} value={crypto}>{crypto}</MenuItem>
                                            ))}
                                        </Select>
                                    </FormControl>

                                    <TextField
                                        fullWidth
                                        label="Transaction Hash"
                                        placeholder="Enter the transaction hash from your crypto wallet"
                                        value={transactionHash}
                                        onChange={(e) => setTransactionHash(e.target.value)}
                                        sx={{
                                            mb: 2,
                                            '& .MuiOutlinedInput-root': {
                                                color: themeColors.textPrimary,
                                                '& fieldset': {
                                                    borderColor: `${themeColors.textSecondary}33`,
                                                },
                                                '&:hover fieldset': {
                                                    borderColor: themeColors.primary,
                                                },
                                            },
                                            '& .MuiInputLabel-root': {
                                                color: themeColors.textSecondary,
                                            },
                                        }}
                                    />

                                    <Button
                                        variant="contained"
                                        fullWidth
                                        size="large"
                                        onClick={handleSubmitPayment}
                                        disabled={submittingPayment || !transactionHash.trim()}
                                        sx={{
                                            backgroundColor: themeColors.primary,
                                            color: themeColors.background,
                                            py: 1.5,
                                            '&:hover': {
                                                backgroundColor: themeColors.primary,
                                                filter: 'brightness(1.1)',
                                            },
                                        }}
                                    >
                                        {submittingPayment ? <CircularProgress size={24} /> : 'Submit Payment'}
                                    </Button>
                                </Box>
                            </>
                        ) : (
                            <>
                                <Typography variant="body2" sx={{ color: themeColors.textSecondary, mb: 3, textAlign: 'center' }}>
                                    Click the button below to open the payment page. You can pay with BTC, ETH, USDT, or any of 200+ cryptocurrencies via NOWPayments.
                                </Typography>
                                
                                <Button
                                    variant="contained"
                                    size="large"
                                    fullWidth
                                    startIcon={<OpenIcon />}
                                    onClick={handleOpenPayment}
                                    sx={{
                                        backgroundColor: '#0088cc',
                                        color: '#fff',
                                        py: 1.5,
                                        mb: 2,
                                        '&:hover': {
                                            backgroundColor: '#006699',
                                        }
                                    }}
                                >
                                    Open NOWPayments
                                </Button>
                                
                                <Box sx={{ mt: 2, textAlign: 'center' }}>
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
