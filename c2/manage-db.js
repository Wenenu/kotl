#!/usr/bin/env node

/**
 * Database Management Script
 * 
 * Usage:
 *   node manage-db.js list-users
 *   node manage-db.js create-user <username> <password>
 *   node manage-db.js change-password <username> <new-password>
 *   node manage-db.js delete-user <username>
 *   node manage-db.js deactivate-user <username>
 *   node manage-db.js activate-user <username>
 *   node manage-db.js reset-password <username> <new-password>
 *   node manage-db.js keep-only-users <username1> [username2] [username3] ...
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

async function listUsers() {
    console.log('\n=== Users in Database ===\n');
    const users = userDb.getAll();
    
    if (users.length === 0) {
        console.log('No users found in database.\n');
        return;
    }
    
    users.forEach((user, index) => {
        console.log(`${index + 1}. Username: ${user.username}`);
        console.log(`   ID: ${user.id}`);
        console.log(`   Created: ${user.created_at}`);
        console.log(`   Last Login: ${user.last_login || 'Never'}`);
        console.log(`   Active: ${user.is_active ? 'Yes' : 'No'}`);
        console.log('');
    });
}

async function createUser(username, password) {
    if (!username || !password) {
        console.error('Error: Username and password are required');
        console.log('Usage: node manage-db.js create-user <username> <password>');
        process.exit(1);
    }
    
    if (password.length < 6) {
        console.error('Error: Password must be at least 6 characters long');
        process.exit(1);
    }
    
    try {
        // Check if user already exists
        const existing = userDb.findByUsername(username);
        if (existing) {
            console.error(`Error: User '${username}' already exists`);
            process.exit(1);
        }
        
        // Hash password with bcrypt (automatically includes salt)
        // bcrypt uses a cost factor of 10 rounds (configurable)
        const passwordHash = bcrypt.hashSync(password, 10);
        
        // Create user
        const newUser = userDb.create(username, passwordHash);
        
        console.log(`\n✓ User '${username}' created successfully!`);
        console.log(`  User ID: ${newUser.id}`);
        console.log(`  Password: Hashed with bcrypt (salt included automatically)\n`);
    } catch (error) {
        if (error.message === 'Username already exists') {
            console.error(`Error: User '${username}' already exists`);
        } else {
            console.error('Error creating user:', error.message);
        }
        process.exit(1);
    }
}

async function changePassword(username, newPassword) {
    if (!username || !newPassword) {
        console.error('Error: Username and new password are required');
        console.log('Usage: node manage-db.js change-password <username> <new-password>');
        process.exit(1);
    }
    
    if (newPassword.length < 6) {
        console.error('Error: Password must be at least 6 characters long');
        process.exit(1);
    }
    
    const user = userDb.findByUsername(username);
    if (!user) {
        console.error(`Error: User '${username}' not found`);
        process.exit(1);
    }
    
    // Hash new password with bcrypt
    const passwordHash = bcrypt.hashSync(newPassword, 10);
    userDb.updatePassword(username, passwordHash);
    
    console.log(`\n✓ Password changed successfully for user '${username}'\n`);
}

async function resetPassword(username, newPassword) {
    // Same as changePassword but without requiring old password
    await changePassword(username, newPassword);
}

async function deleteUser(username) {
    if (!username) {
        console.error('Error: Username is required');
        console.log('Usage: node manage-db.js delete-user <username>');
        process.exit(1);
    }
    
    const user = userDb.findByUsername(username);
    if (!user) {
        console.error(`Error: User '${username}' not found`);
        process.exit(1);
    }
    
    const answer = await question(`Are you sure you want to DELETE user '${username}'? (yes/no): `);
    if (answer.toLowerCase() !== 'yes') {
        console.log('Operation cancelled.');
        rl.close();
        return;
    }
    
    // Note: We need to add a delete method to userDb
    const { db } = require('./database');
    db.prepare('DELETE FROM users WHERE username = ?').run(username);
    
    console.log(`\n✓ User '${username}' deleted successfully\n`);
}

async function deactivateUser(username) {
    if (!username) {
        console.error('Error: Username is required');
        console.log('Usage: node manage-db.js deactivate-user <username>');
        process.exit(1);
    }
    
    const user = userDb.findByUsername(username);
    if (!user) {
        console.error(`Error: User '${username}' not found`);
        process.exit(1);
    }
    
    const { db } = require('./database');
    db.prepare('UPDATE users SET is_active = 0 WHERE username = ?').run(username);
    
    console.log(`\n✓ User '${username}' deactivated successfully\n`);
}

async function activateUser(username) {
    if (!username) {
        console.error('Error: Username is required');
        console.log('Usage: node manage-db.js activate-user <username>');
        process.exit(1);
    }
    
    const user = userDb.findByUsername(username);
    if (!user) {
        console.error(`Error: User '${username}' not found`);
        process.exit(1);
    }
    
    const { db } = require('./database');
    db.prepare('UPDATE users SET is_active = 1 WHERE username = ?').run(username);
    
    console.log(`\n✓ User '${username}' activated successfully\n`);
}

async function keepOnlyUsers(...usernames) {
    if (!usernames || usernames.length === 0) {
        console.error('Error: At least one username is required');
        console.log('Usage: node manage-db.js keep-only-users <username1> [username2] [username3] ...');
        process.exit(1);
    }
    
    const { db } = require('./database');
    
    // Get all users (including inactive ones)
    const allUsers = db.prepare('SELECT id, username, is_active FROM users').all();
    
    // Remove duplicates from usernames to keep
    const usernamesToKeep = [...new Set(usernames)];
    
    // Check which users exist (check all users, not just active ones)
    const existingUsers = usernamesToKeep.filter(u => {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(u);
        return user !== undefined;
    });
    
    if (existingUsers.length === 0) {
        console.error('Error: None of the specified usernames exist in the database');
        process.exit(1);
    }
    
    // Show what will be kept and deleted
    console.log('\n=== Users to KEEP ===');
    existingUsers.forEach(u => {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(u);
        const status = user.is_active ? 'Active' : 'Inactive';
        console.log(`  - ${u} (ID: ${user.id}, Status: ${status})`);
    });
    
    const usersToDelete = allUsers.filter(u => !usernamesToKeep.includes(u.username));
    
    if (usersToDelete.length === 0) {
        console.log('\n✓ No users to delete. All specified users already exist and no other users found.\n');
        rl.close();
        return;
    }
    
    console.log('\n=== Users to DELETE ===');
    usersToDelete.forEach(u => {
        const status = u.is_active ? 'Active' : 'Inactive';
        console.log(`  - ${u.username} (ID: ${u.id}, Status: ${status})`);
    });
    
    // Warn about non-existent usernames
    const missingUsers = usernamesToKeep.filter(u => !existingUsers.includes(u));
    if (missingUsers.length > 0) {
        console.log('\n⚠️  WARNING: The following usernames do not exist and will be skipped:');
        missingUsers.forEach(u => console.log(`  - ${u}`));
    }
    
    const answer = await question(`\nAre you sure you want to DELETE ${usersToDelete.length} user(s) and keep only the ${existingUsers.length} specified user(s)? (yes/no): `);
    if (answer.toLowerCase() !== 'yes') {
        console.log('Operation cancelled.');
        rl.close();
        return;
    }
    
    // Delete all users except the ones to keep
    const placeholders = usernamesToKeep.map(() => '?').join(',');
    const result = db.prepare(`DELETE FROM users WHERE username NOT IN (${placeholders})`).run(...usernamesToKeep);
    
    console.log(`\n✓ Successfully deleted ${result.changes} user(s)`);
    console.log(`✓ Kept ${existingUsers.length} user(s): ${existingUsers.join(', ')}\n`);
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
                
            case 'create-user':
                await createUser(args[0], args[1]);
                break;
                
            case 'change-password':
                await changePassword(args[0], args[1]);
                break;
                
            case 'reset-password':
                await resetPassword(args[0], args[1]);
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
                
            case 'keep-only-users':
                await keepOnlyUsers(...args);
                break;
                
            default:
                console.log(`
Database Management Tool

Usage:
  node manage-db.js <command> [arguments]

Commands:
  list-users                    List all users in the database
  create-user <user> <pass>    Create a new user with hashed password
  change-password <user> <pass> Change a user's password
  reset-password <user> <pass>  Reset a user's password (admin only)
  delete-user <user>            Delete a user from the database
  deactivate-user <user>        Deactivate a user account
  activate-user <user>          Activate a user account
  keep-only-users <u1> [u2] [u3] ... Delete all users except the specified usernames

Password Security:
  - All passwords are hashed using bcrypt with 10 salt rounds
  - Each password gets a unique salt automatically
  - Passwords must be at least 6 characters long

Examples:
  node manage-db.js list-users
  node manage-db.js create-user admin securepassword123
  node manage-db.js change-password admin newpassword456
  node manage-db.js deactivate-user olduser
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

