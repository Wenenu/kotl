#!/bin/bash

# Setup .env file with secure values
# Run this script on your server to create a .env file

if [ -f ".env" ]; then
    echo "⚠️  .env file already exists!"
    read -p "Do you want to overwrite it? (yes/no): " answer
    if [ "$answer" != "yes" ]; then
        echo "Aborted."
        exit 0
    fi
fi

# Generate a secure JWT secret
JWT_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")

# Prompt for admin credentials
echo "Setting up .env file..."
echo ""
read -p "Enter default admin username (default: admin): " ADMIN_USERNAME
ADMIN_USERNAME=${ADMIN_USERNAME:-admin}

read -sp "Enter default admin password (default: changeme123): " ADMIN_PASSWORD
ADMIN_PASSWORD=${ADMIN_PASSWORD:-changeme123}
echo ""

read -p "Enter server port (default: 3001): " PORT
PORT=${PORT:-3001}

# Create .env file
cat > .env << EOF
# Server Configuration
PORT=${PORT}

# JWT Secret Key - REQUIRED! No hardcoded fallback for security.
# This is a randomly generated secret - keep it secure!
JWT_SECRET=${JWT_SECRET}

# Default Admin Credentials (only used on FIRST RUN if database is empty)
# If not set, you must create the first user using: node manage-db.js create-user <username> <password>
DEFAULT_ADMIN_USERNAME=${ADMIN_USERNAME}
DEFAULT_ADMIN_PASSWORD=${ADMIN_PASSWORD}

# Security Notes:
# - All passwords are hashed with bcrypt (includes automatic salting)
# - Each password gets a unique salt automatically
# - Change default password immediately after first login!
# - Use the database management script to manage users: node manage-db.js
EOF

echo ""
echo "✅ .env file created successfully!"
echo ""
echo "⚠️  IMPORTANT SECURITY NOTES:"
echo "   - .env file is in .gitignore and will NOT be committed to git"
echo "   - Keep your JWT_SECRET secure and never share it"
echo "   - Change the default admin password after first login"
echo ""

