#!/bin/bash

# Ubuntu Server Setup Script for Web Panel
# Run this script with: bash setup-ubuntu.sh

set -e

echo "========================================="
echo "Web Panel Ubuntu Server Setup"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo -e "${RED}Please do not run this script as root${NC}"
   exit 1
fi

# Step 1: Update system
echo -e "${GREEN}[1/10] Updating system packages...${NC}"
sudo apt update
sudo apt upgrade -y

# Step 2: Install Node.js
echo -e "${GREEN}[2/10] Installing Node.js...${NC}"
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo bash
    sudo apt install -y nodejs
else
    echo -e "${YELLOW}Node.js is already installed: $(node --version)${NC}"
fi

# Step 3: Install Git
echo -e "${GREEN}[3/10] Installing Git...${NC}"
sudo apt install -y git

# Step 4: Install PM2
echo -e "${GREEN}[4/10] Installing PM2...${NC}"
if ! command -v pm2 &> /dev/null; then
    sudo npm install -g pm2
else
    echo -e "${YELLOW}PM2 is already installed${NC}"
fi

# Step 5: Install nginx
echo -e "${GREEN}[5/10] Installing nginx...${NC}"
if ! command -v nginx &> /dev/null; then
    sudo apt install -y nginx
    sudo systemctl enable nginx
else
    echo -e "${YELLOW}nginx is already installed${NC}"
fi

# Step 6: Check if we're in the webpanel directory
if [ ! -f "server.js" ]; then
    echo -e "${RED}Error: server.js not found. Please run this script from the webpanel directory.${NC}"
    exit 1
fi

# Step 7: Install dependencies
echo -e "${GREEN}[6/10] Installing backend dependencies...${NC}"
npm install

echo -e "${GREEN}[7/10] Installing frontend dependencies...${NC}"
cd client
npm install
cd ..

# Step 8: Setup .env file
echo -e "${GREEN}[8/10] Setting up environment variables...${NC}"
if [ ! -f ".env" ]; then
    if [ -f "env.example" ]; then
        cp env.example .env
        echo -e "${YELLOW}Created .env file from env.example${NC}"
        echo -e "${YELLOW}Please edit .env file and set your JWT_SECRET and other values${NC}"
    else
        echo -e "${RED}env.example not found. Please create .env manually.${NC}"
    fi
else
    echo -e "${YELLOW}.env file already exists${NC}"
fi

# Step 9: Build frontend
echo -e "${GREEN}[9/10] Building frontend...${NC}"
cd client
npm run build
cd ..

# Step 10: Generate JWT secret if not set
if [ -f ".env" ]; then
    if grep -q "change-this-secret-key" .env; then
        echo -e "${YELLOW}Generating a new JWT secret...${NC}"
        NEW_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
        # This is a simple replacement - user should verify
        sed -i "s/JWT_SECRET=.*/JWT_SECRET=$NEW_SECRET/" .env
        echo -e "${GREEN}JWT secret generated and updated in .env${NC}"
    fi
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "Next steps:"
echo "1. Edit .env file and configure your settings:"
echo "   nano .env"
echo ""
echo "2. Start the application with PM2:"
echo "   pm2 start server.js --name webpanel"
echo "   pm2 save"
echo "   pm2 startup  # Follow the instructions"
echo ""
echo "3. Configure nginx (see DEPLOYMENT.md for details)"
echo ""
echo "4. Setup SSL with Let's Encrypt (optional but recommended):"
echo "   sudo apt install -y certbot python3-certbot-nginx"
echo "   sudo certbot --nginx -d your-domain.com"
echo ""
echo "For detailed instructions, see DEPLOYMENT.md"

