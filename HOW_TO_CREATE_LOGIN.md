# How to Create a New Login

There are two ways to create a new user account for the web panel:

## Method 1: Using the Command Line Tool (Recommended)

On your server, navigate to the webpanel directory and run:

```bash
cd /opt/kotl/webpanel
node manage-db.js create-user <username> <password>
```

**Example:**
```bash
node manage-db.js create-user account mypassword123
```

**Requirements:**
- Username must be unique
- Password must be at least 6 characters long
- Password is automatically hashed with bcrypt (salt included)

## Method 2: Using the API (Requires Authentication)

If you're already logged in, you can create a new user via the API:

```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"username": "newuser", "password": "password123"}'
```

## Other Useful Commands

**List all users:**
```bash
node manage-db.js list-users
```

**Change a user's password:**
```bash
node manage-db.js change-password <username> <new-password>
```

**Delete a user:**
```bash
node manage-db.js delete-user <username>
```

**Deactivate a user (prevent login):**
```bash
node manage-db.js deactivate-user <username>
```

**Activate a user:**
```bash
node manage-db.js activate-user <username>
```

## Security Notes

- All passwords are hashed using bcrypt with 10 salt rounds
- Each password gets a unique salt automatically
- Never store passwords in plain text
- Change default passwords immediately after first login

