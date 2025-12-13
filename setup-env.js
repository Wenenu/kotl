#!/usr/bin/env node

/**
 * Setup .env file with secure values
 * Run: node setup-env.js
 */

const fs = require('fs');
const crypto = require('crypto');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function question(prompt) {
    return new Promise((resolve) => {
        rl.question(prompt, resolve);
    });
}

async function setupEnv() {
    console.log('Setting up .env file...\n');
    
    // Check if .env already exists
    if (fs.existsSync('.env')) {
        const answer = await question('⚠️  .env file already exists! Overwrite? (yes/no): ');
        if (answer.toLowerCase() !== 'yes') {
            console.log('Aborted.');
            rl.close();
            return;
        }
    }
    
    // Generate secure JWT secret
    const jwtSecret = crypto.randomBytes(64).toString('hex');
    
    // Get user input
    const adminUsername = await question('Enter default admin username (default: admin): ') || 'admin';
    const adminPassword = await question('Enter default admin password (default: changeme123): ') || 'changeme123';
    const port = await question('Enter server port (default: 3001): ') || '3001';
    
    // Create .env content
    const envContent = `# Server Configuration
PORT=${port}

# JWT Secret Key - REQUIRED! No hardcoded fallback for security.
# This is a randomly generated secret - keep it secure!
JWT_SECRET=${jwtSecret}

# Default Admin Credentials (only used on FIRST RUN if database is empty)
# If not set, you must create the first user using: node manage-db.js create-user <username> <password>
DEFAULT_ADMIN_USERNAME=${adminUsername}
DEFAULT_ADMIN_PASSWORD=${adminPassword}

# Security Notes:
# - All passwords are hashed with bcrypt (includes automatic salting)
# - Each password gets a unique salt automatically
# - Change default password immediately after first login!
# - Use the database management script to manage users: node manage-db.js
`;
    
    // Write .env file
    fs.writeFileSync('.env', envContent);
    
    console.log('\n✅ .env file created successfully!');
    console.log('\n⚠️  IMPORTANT SECURITY NOTES:');
    console.log('   - .env file is in .gitignore and will NOT be committed to git');
    console.log('   - Keep your JWT_SECRET secure and never share it');
    console.log('   - Change the default admin password after first login');
    console.log(`   - JWT_SECRET: ${jwtSecret.substring(0, 20)}... (full secret saved in .env)\n`);
    
    rl.close();
}

setupEnv().catch(error => {
    console.error('Error:', error);
    rl.close();
    process.exit(1);
});

