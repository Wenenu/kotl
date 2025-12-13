# Database Management Guide

## Password Security

**All passwords are automatically hashed and salted using bcrypt:**
- Each password gets a **unique salt** automatically (bcrypt handles this)
- **10 salt rounds** are used (configurable, but 10 is the default)
- Passwords are **never stored in plain text**
- The salt is embedded in the hash, so you don't need to manage salts separately

## No Hardcoded Credentials

✅ **Removed all hardcoded credentials:**
- JWT_SECRET must be set in `.env` (no fallback)
- Default admin credentials only from `.env` (no hardcoded defaults)
- If `.env` variables are missing, you must use the management script

## Database Management Script

Use `manage-db.js` to manage users directly:

### List All Users
```bash
node manage-db.js list-users
```

### Create a New User
```bash
node manage-db.js create-user <username> <password>
```
Example:
```bash
node manage-db.js create-user admin securepassword123
```

### Change a User's Password
```bash
node manage-db.js change-password <username> <new-password>
```

### Reset a User's Password (Admin)
```bash
node manage-db.js reset-password <username> <new-password>
```

### Delete a User
```bash
node manage-db.js delete-user <username>
```

### Deactivate a User
```bash
node manage-db.js deactivate-user <username>
```

### Activate a User
```bash
node manage-db.js activate-user <username>
```

## API Endpoints for User Management

All endpoints require authentication (JWT token).

### List Users
```bash
curl -X GET http://localhost:3001/api/auth/users \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Create User
```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"username": "newuser", "password": "password123"}'
```

### Change Your Own Password
```bash
curl -X POST http://localhost:3001/api/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"oldPassword": "oldpass", "newPassword": "newpass"}'
```

### Reset Another User's Password (Admin)
```bash
curl -X POST http://localhost:3001/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"username": "targetuser", "newPassword": "newpass123"}'
```

### Delete User
```bash
curl -X DELETE http://localhost:3001/api/auth/users/targetuser \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Activate/Deactivate User
```bash
curl -X PATCH http://localhost:3001/api/auth/users/targetuser \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"is_active": false}'
```

## Direct SQLite Access

You can also access the database directly using SQLite:

```bash
sqlite3 webpanel.db
```

### Useful SQL Queries

```sql
-- List all users (passwords are hashed)
SELECT id, username, created_at, last_login, is_active FROM users;

-- Check if a user exists
SELECT username FROM users WHERE username = 'admin';

-- See login attempts
SELECT * FROM login_attempts ORDER BY attempted_at DESC LIMIT 10;

-- Count logs
SELECT COUNT(*) FROM logs;
```

**⚠️ WARNING:** Never modify password hashes directly in SQL! Always use the management script or API, which properly hashes passwords with bcrypt.

## Initial Setup

### Option 1: Using Environment Variables

1. Copy `env.example` to `.env`
2. Set `DEFAULT_ADMIN_USERNAME` and `DEFAULT_ADMIN_PASSWORD`
3. Start the server - it will create the admin user automatically

### Option 2: Using Management Script

1. Start the server (it will create an empty database)
2. Create the first user:
   ```bash
   node manage-db.js create-user admin your-secure-password
   ```

## Security Best Practices

1. ✅ **Change default passwords immediately** after first login
2. ✅ **Use strong passwords** (at least 12 characters, mixed case, numbers, symbols)
3. ✅ **Set JWT_SECRET** to a strong random value in `.env`
4. ✅ **Never commit `.env`** to version control
5. ✅ **Regularly review** login attempts: `SELECT * FROM login_attempts WHERE success = 0`
6. ✅ **Deactivate unused accounts** instead of deleting them (for audit trail)

## Password Hashing Details

- **Algorithm:** bcrypt
- **Salt Rounds:** 10 (configurable)
- **Salt:** Automatically generated and embedded in hash
- **Format:** `$2a$10$...` (includes algorithm, cost, salt, and hash)

Example hash:
```
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
```

This hash includes:
- `$2a$` - bcrypt algorithm identifier
- `10` - cost factor (2^10 = 1024 iterations)
- `N9qo8uLOickgx2ZMRZoMye` - 22 character salt
- `IjZAgcfl7p92ldGxad68LJZdL17lhWy` - 31 character hash

