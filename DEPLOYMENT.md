# Ubuntu Server Deployment Guide

This guide will help you deploy the web panel on an Ubuntu server with nginx as a reverse proxy.

## Prerequisites

- Ubuntu server (18.04 or later)
- Root or sudo access
- Domain name (optional, but recommended)
- SSH access to your server

## Step 1: Update System

```bash
sudo apt update
sudo apt upgrade -y
```

## Step 2: Install Node.js and npm

```bash
# Install Node.js 18.x (LTS)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo bash
sudo apt install -y nodejs

# Verify installation
node --version
npm --version
```

**Alternative method if the above doesn't work:**
```bash
# Download and run the setup script
curl -fsSL https://deb.nodesource.com/setup_18.x -o /tmp/node_setup.sh
sudo bash /tmp/node_setup.sh
sudo apt install -y nodejs
```

## Step 3: Install Git

```bash
sudo apt install -y git
```

## Step 4: Clone the Repository

**Recommended location: `/opt/webpanel`**

The `/opt` directory is the standard location for optional/third-party software on Linux systems. This keeps your application organized and separate from system files.

```bash
cd /opt
sudo git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git webpanel
sudo chown -R $USER:$USER /opt/webpanel
cd /opt/webpanel
```

**Explanation of `$USER:$USER`:**
- `$USER` is an environment variable that contains your current username
- `chown` format is `owner:group`
- `$USER:$USER` means: set the owner to your username AND set the group to your username's primary group
- This gives you full read/write permissions to the directory without needing `sudo` for every operation

**Alternative:** If you want to be explicit, you can replace `$USER:$USER` with your actual username:
```bash
sudo chown -R yourusername:yourusername /opt/webpanel
```

**Alternative locations:**
- `/home/your-username/webpanel` - If you prefer a user directory
- `/var/www/webpanel` - If you want it alongside other web applications
- `/srv/webpanel` - For site-specific data

**Note:** If you choose a different location, make sure to update all paths in the nginx configuration and any scripts accordingly.

## Step 5: Install Dependencies

```bash
# Install backend dependencies
npm install

# Install frontend dependencies
cd client
npm install
cd ..
```

## Step 6: Configure Environment Variables

```bash
# Copy the example environment file
cp env.example .env

# Edit the .env file
nano .env
```

Update the following values in `.env`:
```
PORT=3001
JWT_SECRET=your-very-strong-random-secret-key-here
DEFAULT_ADMIN_USERNAME=admin
DEFAULT_ADMIN_PASSWORD=your-secure-password-here
```

**Generate a strong JWT secret:**
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

## Step 7: Build the Frontend

```bash
cd client
npm run build
cd ..
```

## Step 8: Install PM2 (Process Manager)

PM2 will keep your Node.js application running and restart it automatically if it crashes.

```bash
sudo npm install -g pm2

# Start the application
pm2 start server.js --name webpanel

# Save PM2 configuration
pm2 save

# Setup PM2 to start on boot
pm2 startup
# Follow the instructions it provides (usually involves running a sudo command)
```

## Step 9: Configure Nginx

### Create Nginx Configuration File

**Option 1: Use the setup script (easiest)**

If you cloned the repository, run the setup script:

```bash
cd /opt/webpanel
sudo bash setup-nginx.sh
```

**Option 2: Copy from included config file (recommended)**

If you cloned the repository, you can copy the pre-configured file:

```bash
sudo cp /opt/webpanel/nginx-webpanel.conf /etc/nginx/sites-available/webpanel
```

**Option 3: Use cat with heredoc (if you need to type it manually)**

**IMPORTANT:** Make sure to use `cat >` (with the `>` redirect operator):

```bash
sudo cat > /etc/nginx/sites-available/webpanel << 'EOF'
server {
    listen 80;
    server_name 62.60.179.121;

    # Increase client body size for large uploads
    client_max_body_size 50M;

    # Proxy all requests to Node.js server
    location / {
        proxy_pass http://localhost:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
EOF
```

**Note:** After typing `EOF` and pressing Enter, the file will be created. Make sure `EOF` is on its own line.

**Note:** If you have a domain name, replace `62.60.179.121` with your domain (e.g., `server_name example.com www.example.com;`)

### Enable the Site

```bash
# Create symbolic link
sudo ln -s /etc/nginx/sites-available/webpanel /etc/nginx/sites-enabled/

# Remove default nginx site (optional)
sudo rm /etc/nginx/sites-enabled/default

# Test nginx configuration
sudo nginx -t

# Restart nginx
sudo systemctl restart nginx
```

## Step 10: Configure Firewall

```bash
# Allow HTTP and HTTPS
sudo ufw allow 'Nginx Full'
# Or if you only want HTTP:
# sudo ufw allow 'Nginx HTTP'

# Enable firewall if not already enabled
sudo ufw enable
```

## Step 11: Setup SSL with Let's Encrypt (Recommended)

If you have a domain name, set up free SSL certificates:

```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Get SSL certificate (replace with your domain)
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Certbot will automatically configure nginx and set up auto-renewal
```

## Step 12: Verify Installation

1. Open your browser and navigate to `http://your-server-ip` or `https://your-domain.com`
2. You should see the login page
3. Login with the default credentials (or the ones you set in `.env`)

## Step 13: Change Default Password

**Important:** Change the default admin password immediately after first login!

You can do this via the API:

```bash
# First, login to get a token
TOKEN=$(curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"your-old-password"}' \
  | grep -o '"token":"[^"]*' | cut -d'"' -f4)

# Change password
curl -X POST http://localhost:3001/api/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"oldPassword":"your-old-password","newPassword":"your-new-secure-password"}'
```

## Useful Commands

### PM2 Commands

```bash
# View application status
pm2 status

# View logs
pm2 logs webpanel

# Restart application
pm2 restart webpanel

# Stop application
pm2 stop webpanel

# View real-time monitoring
pm2 monit
```

### Nginx Commands

```bash
# Test configuration
sudo nginx -t

# Reload nginx (after config changes)
sudo systemctl reload nginx

# Restart nginx
sudo systemctl restart nginx

# View nginx status
sudo systemctl status nginx
```

### Application Logs

```bash
# PM2 logs
pm2 logs webpanel

# Application logs (if you add file logging)
tail -f /opt/webpanel/logs.json
```

## Troubleshooting

### Application won't start

1. Check PM2 logs: `pm2 logs webpanel`
2. Verify Node.js is installed: `node --version`
3. Check if port 3001 is in use: `sudo netstat -tulpn | grep 3001`
4. Verify `.env` file exists and has correct values

### Nginx 502 Bad Gateway

1. Check if the Node.js app is running: `pm2 status`
2. Verify the app is listening on port 3001: `curl http://localhost:3001`
3. Check nginx error logs: `sudo tail -f /var/log/nginx/error.log`

### Can't access from browser

1. Check firewall: `sudo ufw status`
2. Verify nginx is running: `sudo systemctl status nginx`
3. Check nginx configuration: `sudo nginx -t`

### SSL Certificate Issues

1. Ensure your domain points to your server's IP
2. Check DNS: `dig your-domain.com`
3. Verify port 80 and 443 are open: `sudo ufw status`

## Security Recommendations

1. **Change default credentials** immediately after deployment
2. **Use strong JWT secret** - generate a new one for production
3. **Enable HTTPS** with Let's Encrypt
4. **Keep system updated**: `sudo apt update && sudo apt upgrade`
5. **Regular backups** of `users.json` and `logs.json`
6. **Firewall configuration** - only allow necessary ports
7. **Monitor logs** regularly for suspicious activity

## Backup

Create a backup script:

```bash
sudo nano /opt/webpanel/backup.sh
```

Add:
```bash
#!/bin/bash
BACKUP_DIR="/opt/backups/webpanel"
DATE=$(date +%Y%m%d_%H%M%S)
mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/webpanel_$DATE.tar.gz /opt/webpanel/users.json /opt/webpanel/logs.json
# Keep only last 7 days of backups
find $BACKUP_DIR -name "webpanel_*.tar.gz" -mtime +7 -delete
```

Make it executable:
```bash
chmod +x /opt/webpanel/backup.sh
```

Add to crontab (daily backup at 2 AM):
```bash
crontab -e
# Add this line:
0 2 * * * /opt/webpanel/backup.sh
```

## Updating the Application

```bash
cd /opt/webpanel

# Pull latest changes
git pull

# Install/update dependencies
npm install
cd client
npm install
cd ..

# Rebuild frontend
cd client
npm run build
cd ..

# Restart application
pm2 restart webpanel
```

## Support

For issues, check:
- PM2 logs: `pm2 logs webpanel`
- Nginx logs: `sudo tail -f /var/log/nginx/error.log`
- Application files in `/opt/webpanel`

