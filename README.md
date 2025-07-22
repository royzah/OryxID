# OryxID - Modern OAuth2/OpenID Connect Server

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![React Version](https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react)
![TypeScript Version](https://img.shields.io/badge/TypeScript-5+-3178C6?style=for-the-badge&logo=typescript)

A modern, high-performance OAuth2/OpenID Connect server built with Go and React. OryxID provides enterprise-grade authentication and authorization services with a focus on performance, security, and ease of deployment.

## 🚀 Features

- **OAuth 2.0 & OpenID Connect**: Full support for authorization code, client credentials, and refresh token flows
- **JWT Tokens**: Industry-standard JSON Web Tokens with customizable claims
- **High Performance**: Built with Go for exceptional speed and low resource usage
- **Modern UI**: React-based admin panel with real-time updates
- **Multi-tenancy**: Support for multiple applications and audiences
- **Flexible Scopes**: Fine-grained permission management
- **Self-hosted**: Complete data sovereignty and control
- **Production Ready**: Built-in health checks, metrics, and logging
- **Container Native**: Optimized for Docker and Kubernetes deployments

## 📋 Table of Contents

- [Architecture](#️-architecture)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Configuration](#️-configuration)
- [API Documentation](#-api-documentation)
- [Development](#️-development)
- [Production Deployment](#-production-deployment)

## 🏗️ Architecture

```text
OryxID/
├── backend/                 # Go backend service
│   ├── cmd/                # Application entry points
│   ├── internal/           # Internal packages
│   ├── pkg/               # Public packages
│   └── migrations/        # Database migrations
├── frontend/              # React frontend
│   ├── src/              # Source code
│   └── public/           # Static assets
├── docker/               # Docker configurations
├── k8s/                 # Kubernetes manifests
└── docs/               # Documentation
```

### Technology Stack

#### Backend

- **Language**: Go 1.21+
- **Web Framework**: Gin
- **Database**: PostgreSQL with GORM
- **Cache**: Redis for sessions and rate limiting
- **JWT**: golang-jwt/jwt
- **Validation**: go-playground/validator

#### Frontend

- **Framework**: React 18 with TypeScript
- **Styling**: Tailwind CSS + Radix UI
- **State Management**: Zustand
- **Build Tool**: Vite
- **API Client**: Tanstack Query

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Make (optional, for convenience commands)
- Git

### One-Command Setup

```bash
# Clone the repository
git clone https://github.com/tiiuae/oryxid.git
cd oryxid

# Initial setup (generates keys, installs dependencies)
make setup

# Start the development environment
make dev
```

The application will be available at:

- **Admin Panel**: [http://localhost:3000](http://localhost:3000)
- **OAuth/API Server**: [http://localhost:9000](http://localhost:9000)

Default admin credentials:

- **Username**: admin
- **Password**: admin123

## 📦 Installation

### Using Docker Compose (Recommended)

1. Clone the repository:

```bash
git clone https://github.com/tiiuae/oryxid.git
cd oryxid
```

1. Generate RSA keys for JWT signing:

```bash
make generate-keys
# or manually:
mkdir -p docker/certs
openssl genrsa -out docker/certs/private_key.pem 4096
openssl rsa -in docker/certs/private_key.pem -pubout -out docker/certs/public_key.pem
```

2. Create environment file:

```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Start the services:

```bash
docker-compose -f docker/docker-compose.yml up -d
```

### Manual Installation

#### Backend Installation

```bash
cd backend
go mod download
go build -o bin/oryxid cmd/server/main.go
./bin/oryxid
```

#### Frontend Installation

```bash
cd frontend
npm install
npm run build
npm run preview
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
# Database
DB_USER=oryxid
DB_PASSWORD=secure_password
DB_NAME=oryxid

# Redis
REDIS_PASSWORD=redis_secret

# OAuth
OAUTH_ISSUER=https://auth.yourdomain.com

# Admin
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=secure_admin_password

# Frontend
VITE_API_URL=http://localhost:9000
```

### Backend Configuration

The backend can be configured via environment variables or a `config.yaml` file:

```yaml
server:
  host: 0.0.0.0
  port: 9000
  mode: release

database:
  host: localhost
  port: 5432
  user: oryxid
  password: secure_password
  name: oryxid

oauth:
  issuer: https://auth.yourdomain.com
  access_token_lifespan: 1h
  refresh_token_lifespan: 720h

security:
  bcrypt_cost: 12
  rate_limit_enabled: true
  pkce_required: true
```

## 📚 API Documentation

### OAuth 2.0 Endpoints

#### Authorization Endpoint

```text
GET /oauth/authorize
```

Parameters:

- `response_type`: `code` or `token`
- `client_id`: Application client ID
- `redirect_uri`: Registered redirect URI
- `scope`: Space-separated scopes
- `state`: CSRF protection
- `code_challenge`: PKCE challenge (required for public clients)
- `code_challenge_method`: `S256` or `plain`

#### Token Endpoint

```text
POST /oauth/token
```

Grant Types:

- `authorization_code`
- `client_credentials`
- `refresh_token`

Example:

```bash
curl -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "client_id:client_secret" \
  -d "grant_type=client_credentials&scope=read:data write:data"
```

#### Token Introspection

```text
POST /oauth/introspect
```

#### Token Revocation

```text
POST /oauth/revoke
```

#### OpenID Connect Discovery

```text
GET /.well-known/openid-configuration
```

#### JWKS Endpoint

```text
GET /.well-known/jwks.json
```

### Admin API

All admin endpoints require authentication via Bearer token.

#### Applications

- `GET /api/v1/applications` - List applications
- `POST /api/v1/applications` - Create application
- `GET /api/v1/applications/:id` - Get application
- `PUT /api/v1/applications/:id` - Update application
- `DELETE /api/v1/applications/:id` - Delete application

#### Scopes

- `GET /api/v1/scopes` - List scopes
- `POST /api/v1/scopes` - Create scope
- `GET /api/v1/scopes/:id` - Get scope
- `PUT /api/v1/scopes/:id` - Update scope
- `DELETE /api/v1/scopes/:id` - Delete scope

## 🛠️ Development

### Backend Development

```bash
# Run backend with hot reload
make backend-run

# Run tests
make backend-test

# Format code
make backend-fmt

# Lint code
make backend-lint
```

### Frontend Development

```bash
# Run frontend dev server
make frontend-run

# Run linter
make frontend-lint

# Format code
make frontend-format
```

### Database Management

```bash
# Run migrations
make db-migrate

# Rollback migration
make db-rollback

# Reset database
make db-reset

# Seed test data
make db-seed
```

## 🚢 Production Deployment

### Docker

Build production images:

```bash
make prod-build
```

### Kubernetes

1. Update the manifests in `k8s/` directory
2. Deploy to your cluster:

```bash
kubectl apply -f k8s/
```

### Security Considerations

1. **Use HTTPS**: Always use TLS in production
2. **Secure Keys**: Rotate JWT signing keys regularly
3. **Strong Passwords**: Use secure passwords for all accounts
4. **Network Policies**: Implement proper network segmentation
5. **Rate Limiting**: Configure appropriate rate limits
6. **CORS**: Configure CORS policies correctly

## 🔒 Security

### Security Features

- PKCE support for public clients
- Token rotation and revocation
- Rate limiting and DDoS protection
- Audit logging
- Encrypted secrets at rest
- CORS and CSP headers
- SQL injection protection
