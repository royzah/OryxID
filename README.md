# 🔐 OryxID - Modern OAuth2/OpenID Connect Server

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![React Version](https://img.shields.io/badge/React-19+-61DAFB?style=for-the-badge&logo=react)
![TypeScript Version](https://img.shields.io/badge/TypeScript-5+-3178C6?style=for-the-badge&logo=typescript)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)
![License](https://img.shields.io/badge/License-Apache_2.0-green?style=for-the-badge)

A **production-ready**, high-performance OAuth2 and OpenID Connect server built with Go and React. OryxID provides enterprise-grade authentication and authorization services with a beautiful, modern admin interface.

---

## ✨ Features

### 🔐 **Security & Authentication**
- **OAuth 2.0 & OpenID Connect** - Full RFC-compliant implementation
- **PKCE Support** - Enhanced security for mobile and SPA applications
- **RS256 JWT Tokens** - Industry-standard token signing
- **CSRF Protection** - Built-in cross-site request forgery prevention
- **Rate Limiting** - Automatic DDoS and brute-force protection
- **Secure Defaults** - Security-first configuration out of the box

### 🎨 **Modern Admin Interface**
- **React 19** - Latest React with hooks and concurrent features
- **Shadcn/UI** - Beautiful, accessible component library
- **TailwindCSS** - Modern utility-first styling
- **Real-time Updates** - TanStack Query for data synchronization
- **Responsive Design** - Mobile-first, works on all devices

### ⚡ **Performance & Scale**
- **High Performance** - Go-powered backend with <1ms latency
- **Optimized Docker Images** - Multi-stage builds, minimal size
- **PostgreSQL** - Reliable, battle-tested database
- **Redis Caching** - Fast session and token storage
- **Horizontal Scaling** - Stateless design, scale infinitely

### 🏢 **Enterprise Features**
- **Multi-tenancy** - Support multiple applications and audiences
- **Audit Logging** - Comprehensive activity tracking for compliance
- **Custom Scopes** - Fine-grained permission control
- **Role-based Access** - Admin and user role management
- **API Audiences** - Separate resource server authorization

---

## 🚀 Quick Start

### Prerequisites

- **Docker** and **Docker Compose** (required)
- **Make** (recommended, or use docker-compose directly)
- **Git**

### ⚡ One-Command Setup

```bash
# 1. Clone the repository
git clone https://github.com/tiiuae/oryxid.git
cd oryxid

# 2. Setup and start (generates keys, starts all services)
make setup && make dev
```

**That's it!** 🎉 The application is now running.

### 🌐 Access the Application

**Open your browser and navigate to:**

```
http://localhost:8080
```

> **Important:** Always access the application via **port 8080** (Nginx proxy), not 3000 or 9000 directly!

**Default Login Credentials:**
- **Username:** `admin`
- **Password:** `admin123`

> ⚠️ **Security:** Change the default password in production! Edit the `.env` file before deploying.

---

## 📦 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      🌐 Nginx (Port 8080)                   │
│                    Reverse Proxy & SSL                      │
└────────────────┬──────────────────────────┬─────────────────┘
                 │                          │
        ┌────────┴────────┐        ┌────────┴────────┐
        │   Frontend      │        │    Backend      │
        │   React + Vite  │        │    Go + Gin     │
        │   Port 3000     │        │    Port 9000    │
        └─────────────────┘        └────────┬────────┘
                                             │
                              ┌──────────────┴──────────────┐
                              │                             │
                     ┌────────┴────────┐        ┌──────────┴─────────┐
                     │  PostgreSQL     │        │      Redis         │
                     │  Port 5432      │        │      Port 6379     │
                     └─────────────────┘        └────────────────────┘
```

### Port Mapping

| Service | Internal Port | External Port | Access URL |
|---------|--------------|---------------|------------|
| **Nginx** (Main Entry) | 80 | 8080 | `http://localhost:8080` |
| **Frontend** | 3000 | 3000 | `http://localhost:3000` (dev only) |
| **Backend API** | 9000 | 9000 | `http://localhost:9000` (testing only) |
| **PostgreSQL** | 5432 | - | Internal only |
| **Redis** | 6379 | - | Internal only |

> **Best Practice:** In production, only expose port 8080 (or 443 with SSL). Keep all other ports internal.

---

## 🛠️ Make Commands Reference

OryxID includes a comprehensive Makefile for easy management:

### Quick Commands

```bash
make setup          # Initial setup (generate keys, create .env)
make up             # Start all services in production mode
make dev            # Start all services in development mode (hot-reload)
make down           # Stop all services
make restart        # Restart all services
make status         # Show service status and health checks
```

### Service Management

```bash
make restart-backend    # Restart only backend
make restart-nginx      # Restart only nginx
make logs               # Show logs from all services
make logs-backend       # Show backend logs only
make logs-frontend      # Show frontend logs only
```

### Development

```bash
make test               # Run all tests (backend + frontend)
make test-backend       # Run backend tests
make test-frontend      # Run frontend tests
make lint               # Run all linters
make lint-backend       # Lint Go code
make lint-frontend      # Lint TypeScript/React code
```

### Docker Management

```bash
make build              # Build all Docker images
make build-no-cache     # Build without cache (clean build)
make pull               # Pull latest base images
make ps                 # Show running containers
```

### Database Operations

```bash
make db-shell           # Open PostgreSQL shell
make db-backup          # Backup database to ./backups/
make db-restore         # Restore from latest backup
make redis-shell        # Open Redis CLI
```

### Production

```bash
make prod-build         # Build production images
make prod-up            # Start in production mode
```

### Cleanup

```bash
make clean              # Stop and remove containers
make clean-volumes      # Remove containers AND data (⚠️ deletes DB!)
make prune              # Clean up Docker system
```

### Monitoring

```bash
make health             # Check service health
make metrics            # View Prometheus metrics
make check-ports        # Check if ports are available
```

### Debugging

```bash
make shell-backend      # Open shell in backend container
make shell-frontend     # Open shell in frontend container
```

---

## 🔧 Configuration

### Environment Variables

The `.env` file contains all configuration. Here are the key variables:

```env
# Server Configuration
SERVER_MODE=debug                    # debug or release
SERVER_PORT=9000                     # Backend API port
FRONTEND_PORT=3000                   # Frontend dev server port
HTTP_PORT=8080                       # Nginx HTTP port
HTTPS_PORT=8443                      # Nginx HTTPS port (when SSL enabled)

# Frontend Build Mode
FRONTEND_BUILD_TARGET=development    # development or production

# Database
DB_HOST=postgres
DB_PORT=5432
DB_USER=oryxid
DB_PASSWORD=oryxid_secret           # ⚠️ Change in production!
DB_NAME=oryxid

# Redis
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=redis_secret          # ⚠️ Change in production!

# OAuth Configuration
OAUTH_ISSUER=http://localhost:9000
OAUTH_ACCESS_TOKEN_LIFESPAN=3600s    # 1 hour
OAUTH_REFRESH_TOKEN_LIFESPAN=2592000s # 30 days

# Admin User (Login Credentials)
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@oryxid.local
ADMIN_PASSWORD=admin123              # ⚠️ CHANGE THIS!

# Security
SECURITY_BCRYPT_COST=12
SECURITY_RATE_LIMIT_ENABLED=true
SECURITY_PKCE_REQUIRED=true
SECURITY_CSRF_ENABLED=true

# Frontend API URL
VITE_API_URL=http://localhost:9000   # Backend API endpoint
```

### SSL/HTTPS Configuration

To enable HTTPS:

1. **Generate or obtain SSL certificates**
2. **Update nginx configuration** in `docker/nginx/conf.d/default.conf`
3. **Uncomment HTTPS server block** at the bottom of the file
4. **Update `.env`** to use HTTPS URLs
5. **Restart nginx:** `make restart-nginx`

---

## 🧪 Testing OAuth Flow

### 1. Create an Application

1. Login to admin panel at `http://localhost:8080`
2. Navigate to **Applications** → **Create Application**
3. Fill in details:
   - **Name:** My Test App
   - **Client ID:** `test-client`
   - **Redirect URIs:** `http://localhost:8080/callback`
   - **Grant Types:** `authorization_code`, `refresh_token`
   - **Scopes:** `openid`, `profile`, `email`
4. **Save** and note the `client_secret`

### 2. Test Authorization Flow

```bash
# Get authorization code
curl -X GET "http://localhost:9000/oauth/authorize?\
response_type=code&\
client_id=test-client&\
redirect_uri=http://localhost:8080/callback&\
scope=openid%20profile%20email&\
state=random-state-value"

# Exchange code for tokens (replace CODE with actual code)
curl -X POST "http://localhost:9000/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "test-client:CLIENT_SECRET" \
  -d "grant_type=authorization_code" \
  -d "code=CODE" \
  -d "redirect_uri=http://localhost:8080/callback"
```

### 3. Introspect Token

```bash
curl -X POST "http://localhost:9000/oauth/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=YOUR_ACCESS_TOKEN"
```

### 4. Get User Info

```bash
curl -X GET "http://localhost:9000/oauth/userinfo" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## 🔍 Troubleshooting

### ❓ "I can't access localhost:3000 or localhost:9000!"

**Solution:** Access the application via **http://localhost:8080** (Nginx proxy)

**Why?** The architecture uses Nginx as a reverse proxy:
- Port **8080** → Routes to frontend and backend
- Port **3000** → Frontend dev server (internal container port)
- Port **9000** → Backend API (internal container port)

In development mode, ports 3000 and 9000 are mapped for direct access when needed, but the **main entry point** is always **8080**.

### ❓ "Services won't start / Port already in use"

```bash
# Check what's using the ports
make check-ports

# If ports are busy, stop conflicting services or change ports in .env
```

### ❓ "Database connection failed"

```bash
# Check PostgreSQL is running
docker ps | grep postgres

# View PostgreSQL logs
make logs | grep postgres

# Reset database (⚠️ deletes all data!)
make clean-volumes && make setup && make dev
```

### ❓ "Frontend shows 'Network Error' or can't reach API"

1. **Check backend is running:**
   ```bash
   curl http://localhost:9000/health
   ```

2. **Verify `VITE_API_URL` in `.env`:**
   ```env
   VITE_API_URL=http://localhost:9000
   ```

3. **Restart services:**
   ```bash
   make restart
   ```

### ❓ "JWT/Token errors"

```bash
# Ensure RSA keys exist
ls -la certs/

# If missing, regenerate keys
make generate-keys

# Restart backend
make restart-backend
```

### ❓ "Docker build fails with npm errors"

This might be due to dependency conflicts. The frontend uses `--legacy-peer-deps` to handle ESLint version conflicts.

```bash
# Clean rebuild
make clean
make build-no-cache
make dev
```

### ❓ "How do I view logs?"

```bash
# All logs
make logs

# Specific service
make logs-backend
make logs-frontend

# Or use docker-compose directly
docker-compose logs -f
```

---

## 🚀 Production Deployment

### Pre-Deployment Checklist

- [ ] Change `ADMIN_PASSWORD` in `.env`
- [ ] Change `DB_PASSWORD` in `.env`
- [ ] Change `REDIS_PASSWORD` in `.env`
- [ ] Set `SERVER_MODE=release` in `.env`
- [ ] Set `FRONTEND_BUILD_TARGET=production` in `.env`
- [ ] Update `OAUTH_ISSUER` to your production domain
- [ ] Update `VITE_API_URL` to your production API URL
- [ ] Configure SSL certificates for HTTPS
- [ ] Set up database backups
- [ ] Configure logging and monitoring
- [ ] Review security settings

### Docker Deployment

```bash
# 1. Build production images
make prod-build

# 2. Start in production mode
make prod-up

# 3. Verify services are healthy
make status
```

### Using Docker Compose

```bash
# Start services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Cloud Deployment

OryxID is cloud-native and works with all major platforms:

- **AWS ECS/EKS**
- **Google Cloud Run / GKE**
- **Azure Container Instances / AKS**
- **DigitalOcean App Platform**
- **Heroku**
- **Fly.io**
- **Railway**

See the [Deployment Guide](./docs/DEPLOYMENT.md) for platform-specific instructions.

---

## 📊 Monitoring & Observability

### Health Checks

```bash
# Application health
curl http://localhost:8080/health

# Backend API health
curl http://localhost:9000/health

# Database connectivity (internal check)
make db-shell
```

### Metrics

OryxID exposes Prometheus-compatible metrics:

```bash
curl http://localhost:9000/metrics
```

**Available Metrics:**
- HTTP request duration
- Request count by endpoint
- Active sessions
- Token generation rate
- Database query performance
- Cache hit/miss ratio

### Logging

- **Backend:** Structured JSON logs with correlation IDs
- **Format:** Configurable via `LOG_FORMAT` (json or text)
- **Level:** Configurable via `LOG_LEVEL` (debug, info, warn, error)

View logs:
```bash
make logs              # All services
make logs-backend      # Backend only
make logs-frontend     # Frontend only
```

---

## 🤝 API Integration

### OpenID Connect Discovery

OryxID exposes a discovery document at:

```
http://localhost:9000/.well-known/openid-configuration
```

### JWKS Endpoint

Public keys for token verification:

```
http://localhost:9000/.well-known/jwks.json
```

### Example: Integrate with Your Application

#### JavaScript/Node.js

```javascript
const OAUTH_CONFIG = {
  issuer: 'http://localhost:9000',
  authorizationEndpoint: 'http://localhost:9000/oauth/authorize',
  tokenEndpoint: 'http://localhost:9000/oauth/token',
  userInfoEndpoint: 'http://localhost:9000/oauth/userinfo',
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'http://localhost:8080/callback',
};

// Redirect user to authorization
function login() {
  const url = `${OAUTH_CONFIG.authorizationEndpoint}?` +
    `response_type=code&` +
    `client_id=${OAUTH_CONFIG.clientId}&` +
    `redirect_uri=${encodeURIComponent(OAUTH_CONFIG.redirectUri)}&` +
    `scope=openid profile email&` +
    `state=${generateRandomState()}`;

  window.location.href = url;
}

// Exchange code for tokens
async function exchangeCode(code) {
  const response = await fetch(OAUTH_CONFIG.tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + btoa(`${OAUTH_CONFIG.clientId}:${OAUTH_CONFIG.clientSecret}`)
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: OAUTH_CONFIG.redirectUri
    })
  });

  return await response.json();
}
```

#### Python

```python
import requests
from requests.auth import HTTPBasicAuth

OAUTH_CONFIG = {
    'issuer': 'http://localhost:9000',
    'token_endpoint': 'http://localhost:9000/oauth/token',
    'client_id': 'your-client-id',
    'client_secret': 'your-client-secret',
}

def exchange_code(code, redirect_uri):
    response = requests.post(
        OAUTH_CONFIG['token_endpoint'],
        auth=HTTPBasicAuth(OAUTH_CONFIG['client_id'], OAUTH_CONFIG['client_secret']),
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri
        }
    )
    return response.json()
```

---

## 📚 Documentation

- **[Backend Documentation](./backend/README.md)** - Go backend architecture
- **[Frontend Documentation](./frontend/README.md)** - React frontend guide
- **[API Reference](./docs/API.md)** - Complete API documentation
- **[OAuth Guide](./docs/OAUTH.md)** - OAuth 2.0 / OIDC implementation details
- **[Security Guide](./docs/SECURITY.md)** - Security best practices
- **[Deployment Guide](./docs/DEPLOYMENT.md)** - Production deployment instructions

---

## 🤝 Contributing

We welcome contributions! Whether it's:

- 🐛 Bug reports
- ✨ Feature requests
- 📝 Documentation improvements
- 🔧 Code contributions

Please see our [Contributing Guide](./CONTRIBUTING.md) for details.

### Development Workflow

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/oryxid.git`
3. **Create a branch:** `git checkout -b feature/amazing-feature`
4. **Make changes** and commit: `git commit -m 'Add amazing feature'`
5. **Run tests:** `make test`
6. **Push:** `git push origin feature/amazing-feature`
7. **Open a Pull Request**

---

## 📄 License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

Built with amazing open-source technologies:

- **[Go](https://go.dev/)** - Programming language
- **[Gin](https://gin-gonic.com/)** - Web framework
- **[GORM](https://gorm.io/)** - ORM library
- **[React](https://react.dev/)** - UI library
- **[Vite](https://vitejs.dev/)** - Build tool
- **[Shadcn/UI](https://ui.shadcn.com/)** - Component library
- **[TailwindCSS](https://tailwindcss.com/)** - CSS framework
- **[TanStack Query](https://tanstack.com/query)** - Data fetching
- **[PostgreSQL](https://www.postgresql.org/)** - Database
- **[Redis](https://redis.io/)** - Caching

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/tiiuae/oryxid/issues)
- **Discussions:** [GitHub Discussions](https://github.com/tiiuae/oryxid/discussions)
- **Documentation:** [Wiki](https://github.com/tiiuae/oryxid/wiki)

---

<div align="center">

**⭐ Star us on GitHub!** — it helps the project grow

[Report Bug](https://github.com/tiiuae/oryxid/issues) · [Request Feature](https://github.com/tiiuae/oryxid/issues) · [Documentation](./docs/)

Made with ❤️ by the OryxID team

</div>
