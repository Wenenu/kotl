# How to Create a New Login

The web panel uses **key-based authentication**. Instead of usernames and passwords, each user has a unique 20-character access key.

## Method 1: Using the Web Panel (Recommended)

1. Go to the login page
2. Click **"Register New Key"**
3. Your unique 20-character access key will be generated
4. **Copy and save the key securely** - it cannot be recovered if lost!
5. Click **"Create Account"** to register the key
6. Use the key to sign in

## Method 2: Using the Command Line Tool

On your server, navigate to the webpanel directory and run:

```bash
cd /opt/kotl/webpanel
node manage-db.js create-key
```

This will generate a new access key and display it. **Save it immediately!**

**Output example:**
```
✓ New access key created successfully!
  User ID: 5

  ╔════════════════════════════════════════╗
  ║  YOUR ACCESS KEY (SAVE THIS!):         ║
  ║                                        ║
  ║  AbCdEfGhIjKlMnOpQrSt  ║
  ║                                        ║
  ╚════════════════════════════════════════╝

  ⚠️  This key cannot be recovered if lost!
  ⚠️  Store it securely!
```

## Other Useful Commands

**List all users (shows truncated keys for security):**
```bash
node manage-db.js list-users
```

**Delete a user:**
```bash
node manage-db.js delete-user <access-key>
```

**Deactivate a user (prevent login):**
```bash
node manage-db.js deactivate-user <access-key>
```

**Activate a user:**
```bash
node manage-db.js activate-user <access-key>
```

## Security Notes

- Access keys are 20 random characters (uppercase/lowercase letters)
- Keys are hashed using bcrypt before being stored in the database
- Each key gets a unique salt automatically
- **Keys cannot be recovered if lost** - create a new account instead
- Store your access key in a secure password manager
- Never share your access key with others

## Lost Your Key?

If you lose your access key:
1. Ask an admin to delete your old account: `node manage-db.js delete-user <old-key>`
2. Register a new account through the web panel or command line
3. Save your new key securely this time!

## Subscription Management

Users need an active subscription to build payloads.

**Set subscription (admin):**
```bash
node manage-db.js set-sub <access-key> <days>
```

**Add days to subscription:**
```bash
node manage-db.js add-sub <access-key> <days>
```

**Remove subscription:**
```bash
node manage-db.js remove-sub <access-key>
```

**Check subscription status:**
```bash
node manage-db.js check-sub <access-key>
```

## CryptoBot Payment Integration (Optional)

Enable automatic crypto payments through Telegram's CryptoBot.

### Setup:

1. Open Telegram and message [@CryptoBot](https://t.me/CryptoBot)
2. Go to **Crypto Pay** → **My Apps** → **Create App**
3. Get your API token
4. Add to your `.env` file:

```bash
CRYPTOBOT_API_TOKEN=503498:AAGT8tv9ON0qNf8tHDJMH4P80RYxjUFOUDF
WEBPANEL_URL=https://naif.wtf
```

5. Set up the webhook URL in CryptoBot:
   - Go to your app settings in CryptoBot
   - Set webhook URL to: `https://naif.wtf/api/payment/webhook`

### How it works:

1. User clicks "Purchase" on a plan
2. Server creates an invoice via CryptoBot API
3. User pays with crypto (BTC, ETH, USDT, TON, etc.)
4. CryptoBot sends webhook when payment is confirmed
5. Subscription is automatically activated

## PM2 Commands Reference

```bash
pm2 list            # show running apps
pm2 logs            # view logs
pm2 logs my-server  # logs for one app
pm2 restart my-server
pm2 stop my-server
pm2 delete my-server
```
