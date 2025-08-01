# OryxID Quick Start Guide

## 🚀 One-Command Setup

```bash
# Clone and setup
git clone https://github.com/tiiuae/oryxid.git
cd oryxid
chmod +x setup.sh
./setup.sh

# Start everything
make up
```

## 📋 Prerequisites

- Docker & Docker Compose installed
- Make (optional but recommended)
- Port 3000 and 9000 available

## 🔧 Configuration

### Login Credentials

The admin panel login credentials are defined in the `.env` file:

```env
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@oryxid.local
ADMIN_PASSWORD=admin123
```

**⚠️ Important**: Change these default credentials before deploying to production!

### Changing Credentials

1. Edit `.env` file:

   ```bash
   nano .env
   # or
   vim .env
   ```

2. Update these values:

   ```env
   ADMIN_USERNAME=your_username
   ADMIN_EMAIL=your_email@domain.com
   ADMIN_PASSWORD=your_secure_password
   ```

3. Restart services:

   ```bash
   make restart
   ```

## 🎯 Available Commands

### Essential Commands

| Command        | Description                 |
| -------------- | --------------------------- |
| `make up`      | Start all services          |
| `make down`    | Stop all services           |
| `make restart` | Restart all services        |
| `make logs`    | View logs from all services |
| `make status`  | Check service status        |
| `make health`  | Check service health        |

### Development Commands

| Command               | Description                               |
| --------------------- | ----------------------------------------- |
| `make dev`            | Start in development mode with hot-reload |
| `make logs-backend`   | View backend logs only                    |
| `make logs-frontend`  | View frontend logs only                   |
| `make shell-backend`  | Open shell in backend container           |
| `make shell-frontend` | Open shell in frontend container          |

### Maintenance Commands

| Command              | Description                              |
| -------------------- | ---------------------------------------- |
| `make clean`         | Stop and remove containers               |
| `make clean-volumes` | Remove containers AND data (⚠️ Warning!) |
| `make prune`         | Clean up unused Docker resources         |
| `make prune-all`     | Aggressive Docker cleanup (⚠️ Warning!)  |
| `make db-backup`     | Backup database                          |
| `make db-restore`    | Restore database from latest backup      |

## 🌐 Access Points

Once running, you can access:

- **Admin Panel**: <http://localhost:3000>
- **API Server**: <http://localhost:9000>
- **OAuth Endpoints**: <http://localhost:9000/oauth/>
- **Health Check**: <http://localhost:9000/health>

## 🔍 Troubleshooting

### Services won't start

1. Check if ports are in use:

   ```bash
   lsof -i :3000
   lsof -i :9000
   ```

2. Check Docker logs:

   ```bash
   make logs
   ```

3. Verify .env file exists:

   ```bash
   ls -la .env
   ```

### Can't login to admin panel

1. Check credentials in .env:

   ```bash
   grep ADMIN .env
   ```

2. Restart services:

   ```bash
   make restart
   ```

3. Check backend logs:

   ```bash
   make logs-backend
   ```

### Database connection issues

1. Check if PostgreSQL is running:

   ```bash
   make status
   ```

2. Try connecting directly:

   ```bash
   make db-shell
   ```

## 📚 Next Steps

1. **Create OAuth Applications**: Login to admin panel and create your first OAuth application
2. **Configure Scopes**: Set up permission scopes for your applications
3. **Test OAuth Flow**: Use the provided test script:

   ```bash
   ./scripts/test-oauth.sh
   ```

## 🛟 Need Help?

- Check the full documentation in `README.md`
- View backend API docs: `backend/README.md`
- View frontend docs: `frontend/README.md`
- Open an issue on GitHub

## 🔐 Security Notes

Before going to production:

1. Change all default passwords in `.env`
2. Use HTTPS (configure in nginx)
3. Update CORS settings for your domains
4. Enable rate limiting
5. Review security settings in `.env`
