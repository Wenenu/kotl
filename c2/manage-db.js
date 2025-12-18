#!/usr/bin/env node

/**
 * Database Management Script - Key-Based Authentication
 * 
 * Usage:
 *   node manage-db.js list-users
 *   node manage-db.js create-key              # Generate a new access key
 *   node manage-db.js delete-user <key>       # Delete by access key
 *   node manage-db.js deactivate-user <key>   # Deactivate by access key
 *   node manage-db.js activate-user <key>     # Activate by access key
 */

require('dotenv').config();
const readline = require('readline');
const bcrypt = require('bcrypt');
const { userDb } = require('./database');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function question(prompt) {
    return new Promise((resolve) => {
        rl.question(prompt, resolve);
    });
}

// Generate a random 20-character key with uppercase and lowercase letters
function generateAccessKey() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let key = '';
    for (let i = 0; i < 20; i++) {
        key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
}

async function listUsers() {
    console.log('\n=== Users in Database ===\n');
    const users = userDb.getAll();
    
    if (users.length === 0) {
        console.log('No users found in database.\n');
        return;
    }
    
    users.forEach((user, index) => {
        // Show truncated key for security (first 8 chars)
        const keyPreview = user.username.length === 20 
            ? user.username.substring(0, 8) + '...' 
            : user.username;
        console.log(`${index + 1}. Key: ${keyPreview}`);
        console.log(`   ID: ${user.id}`);
        console.log(`   Created: ${user.created_at}`);
        console.log(`   Last Login: ${user.last_login || 'Never'}`);
        console.log(`   Active: ${user.is_active ? 'Yes' : 'No'}`);
        console.log('');
    });
}

async function createKey() {
    try {
        const key = generateAccessKey();
        
        // Hash the key with bcrypt
        const keyHash = bcrypt.hashSync(key, 10);
        
        // Create user with key as username
        const newUser = userDb.create(key, keyHash);
        
        console.log(`\n✓ New access key created successfully!`);
        console.log(`  User ID: ${newUser.id}`);
        console.log(`\n  ╔════════════════════════════════════════╗`);
        console.log(`  ║  YOUR ACCESS KEY (SAVE THIS!):         ║`);
        console.log(`  ║                                        ║`);
        console.log(`  ║  ${key}  ║`);
        console.log(`  ║                                        ║`);
        console.log(`  ╚════════════════════════════════════════╝`);
        console.log(`\n  ⚠️  This key cannot be recovered if lost!`);
        console.log(`  ⚠️  Store it securely!\n`);
    } catch (error) {
        if (error.message === 'Username already exists') {
            // Extremely rare - regenerate
            console.log('Key collision detected, regenerating...');
            await createKey();
        } else {
            console.error('Error creating key:', error.message);
            process.exit(1);
        }
    }
}

async function deleteUser(key) {
    if (!key) {
        console.error('Error: Access key is required');
        console.log('Usage: node manage-db.js delete-user <access-key>');
        process.exit(1);
    }
    
    const user = userDb.findByUsername(key);
    if (!user) {
        console.error(`Error: User with that access key not found`);
        process.exit(1);
    }
    
    const answer = await question(`Are you sure you want to DELETE this user? (yes/no): `);
    if (answer.toLowerCase() !== 'yes') {
        console.log('Operation cancelled.');
        rl.close();
        return;
    }
    
    const { db } = require('./database');
    db.prepare('DELETE FROM users WHERE username = ?').run(key);
    
    console.log(`\n✓ User deleted successfully\n`);
}

async function deactivateUser(key) {
    if (!key) {
        console.error('Error: Access key is required');
        console.log('Usage: node manage-db.js deactivate-user <access-key>');
        process.exit(1);
    }
    
    const user = userDb.findByUsername(key);
    if (!user) {
        console.error(`Error: User with that access key not found`);
        process.exit(1);
    }
    
    const { db } = require('./database');
    db.prepare('UPDATE users SET is_active = 0 WHERE username = ?').run(key);
    
    console.log(`\n✓ User deactivated successfully\n`);
}

async function activateUser(key) {
    if (!key) {
        console.error('Error: Access key is required');
        console.log('Usage: node manage-db.js activate-user <access-key>');
        process.exit(1);
    }
    
    // For activation, we might need to check inactive users too
    const { db } = require('./database');
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(key);
    if (!user) {
        console.error(`Error: User with that access key not found`);
        process.exit(1);
    }
    
    db.prepare('UPDATE users SET is_active = 1 WHERE username = ?').run(key);
    
    console.log(`\n✓ User activated successfully\n`);
}

// Main command handler
async function main() {
    const command = process.argv[2];
    const args = process.argv.slice(3);
    
    try {
        switch (command) {
            case 'list-users':
                await listUsers();
                break;
                
            case 'create-key':
                await createKey();
                break;
                
            case 'delete-user':
                await deleteUser(args[0]);
                break;
                
            case 'deactivate-user':
                await deactivateUser(args[0]);
                break;
                
            case 'activate-user':
                await activateUser(args[0]);
                break;
                
            default:
                console.log(`
Database Management Tool (Key-Based Authentication)

Usage:
  node manage-db.js <command> [arguments]

Commands:
  list-users                    List all users in the database
  create-key                    Generate a new access key
  delete-user <key>             Delete a user by their access key
  deactivate-user <key>         Deactivate a user account
  activate-user <key>           Activate a user account

Key Security:
  - Access keys are 20 characters (uppercase/lowercase letters)
  - Keys are hashed with bcrypt before storage
  - Keys cannot be recovered if lost - create a new one instead

Examples:
  node manage-db.js list-users
  node manage-db.js create-key
  node manage-db.js delete-user AbCdEfGhIjKlMnOpQrSt
  node manage-db.js deactivate-user AbCdEfGhIjKlMnOpQrSt
                `);
                process.exit(0);
        }
    } catch (error) {
        console.error('Error:', error.message);
        process.exit(1);
    } finally {
        rl.close();
    }
}

main();
