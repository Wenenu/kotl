# Database Security Guide

## How Secure is the Database?

### ✅ Password Security

**All passwords are hashed with bcrypt:**
- Each password gets a **unique salt automatically** (bcrypt handles this)
- **10 salt rounds** are used (2^10 = 1,024 iterations)
- Passwords are **never stored in plain text**
- The salt is embedded in the hash, so you don't need to manage salts separately

**Example hash format:**
```
$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy
```
- `$2a$` = bcrypt algorithm
- `10` = cost factor (salt rounds)
- `N9qo8uLOickgx2ZMRZoMye` = 22-character salt (unique per password)
- `IjZAgcfl7p92ldGxad68LJZdL17lhWy` = 31-character hash

### ✅ SQL Injection Protection

**All database queries use parameterized statements:**
- Uses `db.prepare()` with `?` placeholders
- User input is never directly concatenated into SQL
- Example: `db.prepare('SELECT * FROM users WHERE username = ?').get(username)`

**Safe:**
```javascript
db.prepare('SELECT * FROM users WHERE username = ?').get(username)
```

**Unsafe (we don't do this):**
```javascript
db.exec(`SELECT * FROM users WHERE username = '${username}'`) // NEVER!
```

### ✅ Authentication Security

- **JWT tokens** with expiration (24 hours)
- **Login attempt tracking** with IP addresses and timestamps
- **Password verification** uses bcrypt.compareSync() (timing-safe)
- **No hardcoded credentials** - all from environment variables

### ✅ Database File Security

**Recommendations:**
1. **File permissions**: Restrict access to database file
   ```bash
   chmod 600 webpanel.db  # Only owner can read/write
   ```

2. **Backup encryption**: Encrypt backups if storing sensitive data
   ```bash
   # Encrypt backup
   tar czf - webpanel.db | openssl enc -aes-256-cbc -out backup.tar.gz.enc
   ```

3. **Regular backups**: Backup the database regularly
   ```bash
   cp webpanel.db webpanel.db.backup.$(date +%Y%m%d)
   ```

### ✅ Access Control

- **User accounts** can be activated/deactivated
- **Login history** is tracked for audit purposes
- **API endpoints** require JWT authentication
- **Password resets** require admin authentication

## Security Checklist

- [x] Passwords hashed with bcrypt (automatic salting)
- [x] SQL injection protection (parameterized queries)
- [x] JWT authentication with expiration
- [x] Login attempt tracking
- [x] No hardcoded credentials
- [x] Environment variables for secrets
- [ ] Database file permissions (set manually)
- [ ] Regular backups (set up manually)
- [ ] HTTPS in production (use Let's Encrypt)
- [ ] Firewall rules (only allow necessary ports)

## Verifying Security

### Check Password Hashes

```bash
sqlite3 webpanel.db "SELECT username, password_hash FROM users;"
```

You should see bcrypt hashes (starting with `$2a$10$`), never plain text passwords.

### Check Login Attempts

```bash
sqlite3 webpanel.db "SELECT * FROM login_attempts ORDER BY attempted_at DESC LIMIT 10;"
```

This shows failed login attempts, which can indicate brute force attacks.

### Check Database File Permissions

```bash
ls -la webpanel.db
```

Should show restricted permissions (600 or 640).

## Best Practices

1. **Change default passwords** immediately
2. **Use strong passwords** (12+ characters, mixed case, numbers, symbols)
3. **Regularly review** login attempts for suspicious activity
4. **Backup database** regularly
5. **Use HTTPS** in production
6. **Keep Node.js and dependencies** updated
7. **Monitor logs** for errors or suspicious activity

