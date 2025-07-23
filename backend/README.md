# OryxID Backend Documentation

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Getting Started](#getting-started)
3. [Configuration](#configuration)
4. [API Reference](#api-reference)
5. [OAuth 2.0 Implementation](#oauth-20-implementation)
6. [Security Features](#security-features)
7. [Database Schema](#database-schema)
8. [Development Guide](#development-guide)
9. [Production Deployment](#production-deployment)
10. [Troubleshooting](#troubleshooting)

## Architecture Overview

OryxID backend is built with a modular, scalable architecture using Go and industry best practices.

### Technology Stack

- **Language**: Go 1.21+
- **Web Framework**: Gin
- **Database**: PostgreSQL with GORM ORM
- **Cache/Session Store**: Redis (optional)
- **Authentication**: JWT (RS256)
- **Configuration**: Viper
- **Validation**: go-playground/validator

### Project Structure

```text
backend/
├── cmd/
│   └── server/
│       └── main.go         # Application entry point
├── internal/
│   ├── auth/               # Authentication middleware
│   ├── config/             # Configuration management
│   ├── database/           # Database models and connection
│   ├── handlers/           # HTTP request handlers
│   ├── middleware/         # HTTP middleware
│   ├── oauth/              # OAuth 2.0 server implementation
│   ├── redis/              # Redis client and operations
│   └── tokens/             # JWT token management
├── pkg/
│   └── crypto/             # Cryptographic utilities
├── migrations/             # Database migrations
├── scripts/                # Utility scripts
└── tests/                  # Test files
```

## Getting Started

### Prerequisites

- Go 1.21 or later
- PostgreSQL 12+
- Redis 6+ (optional, but recommended)
- Make (optional, for convenience)

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/tiiuae/oryxid.git
   cd oryxid/backend
   ```

2. Install dependencies:

   ```bash
   go mod download
   ```

3. Set up environment variables:

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Generate RSA keys for JWT signing:

   ```bash
   mkdir -p certs
   openssl genrsa -out certs/private_key.pem 4096
   openssl rsa -in certs/private_key.pem -pubout -out certs/public_key.pem
   ```

5. Run database migrations:

   ```bash
   go run cmd/migrate/main.go up
   ```

6. Start the server:

   ```bash
   go run cmd/server/main.go
   ```

## Configuration

### Environment Variables

OryxID uses environment variables for configuration. All variables should be prefixed with `ORYXID_`.

#### Server Configuration

| Variable                     | Description                   | Default   |
| ---------------------------- | ----------------------------- | --------- |
| `ORYXID_SERVER_HOST`         | Server bind address           | `0.0.0.0` |
| `ORYXID_SERVER_PORT`         | Server port                   | `9000`    |
| `ORYXID_SERVER_MODE`         | Gin mode (debug/release/test) | `release` |
| `ORYXID_SERVER_READTIMEOUT`  | HTTP read timeout             | `10s`     |
| `ORYXID_SERVER_WRITETIMEOUT` | HTTP write timeout            | `10s`     |

#### Database Configuration

| Variable                   | Description       | Default     |
| -------------------------- | ----------------- | ----------- |
| `ORYXID_DATABASE_HOST`     | PostgreSQL host   | `localhost` |
| `ORYXID_DATABASE_PORT`     | PostgreSQL port   | `5432`      |
| `ORYXID_DATABASE_USER`     | Database user     | `oryxid`    |
| `ORYXID_DATABASE_PASSWORD` | Database password | Required    |
| `ORYXID_DATABASE_NAME`     | Database name     | `oryxid`    |
| `ORYXID_DATABASE_SSLMODE`  | SSL mode          | `disable`   |

#### Redis Configuration

| Variable                | Description    | Default     |
| ----------------------- | -------------- | ----------- |
| `ORYXID_REDIS_HOST`     | Redis host     | `localhost` |
| `ORYXID_REDIS_PORT`     | Redis port     | `6379`      |
| `ORYXID_REDIS_PASSWORD` | Redis password | Optional    |
| `ORYXID_REDIS_DB`       | Redis database | `0`         |

#### OAuth Configuration

| Variable                                 | Description            | Default                     |
| ---------------------------------------- | ---------------------- | --------------------------- |
| `ORYXID_OAUTH_ISSUER`                    | Token issuer URL       | `https://localhost:9000`    |
| `ORYXID_OAUTH_ACCESSTOKENLIFESPAN`       | Access token lifespan  | `3600`                      |
| `ORYXID_OAUTH_REFRESHTOKENLIFESPAN`      | Refresh token lifespan | `2592000`                   |
| `ORYXID_OAUTH_AUTHORIZATIONCODELIFESPAN` | Auth code lifespan     | `600`                       |
| `ORYXID_OAUTH_ALLOWEDORIGINS`            | CORS allowed origins   | `["http://localhost:3000"]` |

#### Security Configuration

| Variable                           | Description            | Default |
| ---------------------------------- | ---------------------- | ------- |
| `ORYXID_SECURITY_BCRYPTCOST`       | BCrypt cost factor     | `12`    |
| `ORYXID_SECURITY_RATELIMITENABLED` | Enable rate limiting   | `true`  |
| `ORYXID_SECURITY_RATELIMITRPS`     | Requests per second    | `100`   |
| `ORYXID_SECURITY_RATELIMITBURST`   | Burst size             | `10`    |
| `ORYXID_SECURITY_PKCEREQUIRED`     | Require PKCE           | `true`  |
| `ORYXID_SECURITY_CSRFENABLED`      | Enable CSRF protection | `true`  |

### Configuration File

Alternatively, you can use a `config.yaml` file:

```yaml
server:
  host: 0.0.0.0
  port: 9000
  mode: release
  readtimeout: 10s
  writetimeout: 10s

database:
  host: localhost
  port: 5432
  user: oryxid
  password: secure_password
  name: oryxid
  sslmode: disable
  maxopenconns: 25
  maxidleconns: 5
  connmaxlifetime: 5m

redis:
  host: localhost
  port: 6379
  password: ""
  db: 0
  poolsize: 10
  minidleconns: 5

oauth:
  issuer: https://auth.example.com
  authorizationcodelifespan: 10m
  accesstokenlifespan: 1h
  refreshtokenlifespan: 720h
  idtokenlifespan: 1h
  allowedorigins:
    - https://app.example.com
    - https://admin.example.com

security:
  bcryptcost: 12
  ratelimitenabled: true
  ratelimitburst: 10
  ratelimitrps: 100
  pkcerequired: true
  csrfenabled: true

jwt:
  privatekeypath: ./certs/private_key.pem
  publickeypath: ./certs/public_key.pem
  kid: default-key-id
```

## API Reference

### Authentication

All API endpoints (except OAuth and public endpoints) require authentication via Bearer token:

```text
Authorization: Bearer <access_token>
```

### Error Responses

All endpoints return errors in the following format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable error message"
}
```

### Admin API Endpoints

#### Applications

##### List Applications

```text
GET /api/v1/applications
```

Query parameters:

- `search` (optional): Search by name or client ID

Response:

```json
[
  {
    "id": "uuid",
    "name": "My Application",
    "client_id": "client_id_here",
    "client_type": "confidential",
    "grant_types": ["authorization_code", "refresh_token"],
    "redirect_uris": ["https://app.example.com/callback"],
    "scopes": [...],
    "created_at": "2025-01-20T10:00:00Z"
  }
]
```

##### Create Application

```text
POST /api/v1/applications
```

Request body:

```json
{
  "name": "My Application",
  "description": "Application description",
  "client_type": "confidential",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "redirect_uris": ["https://app.example.com/callback"],
  "scope_ids": ["uuid1", "uuid2"],
  "skip_authorization": false
}
```

Response includes `client_secret` only on creation.

##### Get Application

```text
GET /api/v1/applications/:id
```

##### Update Application

```text
PUT /api/v1/applications/:id
```

##### Delete Application

```text
DELETE /api/v1/applications/:id
```

#### Scopes

##### List Scopes

```text
GET /api/v1/scopes
```

##### Create Scope

```text
POST /api/v1/scopes
```

Request body:

```json
{
  "name": "read:data",
  "description": "Read access to data",
  "is_default": false
}
```

#### Users

##### List Users (Admin only)

```text
GET /api/v1/users
```

##### Create User (Admin only)

```text
POST /api/v1/users
```

Request body:

```json
{
  "username": "johndoe",
  "email": "john@example.com",
  "password": "secure_password",
  "is_active": true,
  "is_admin": false,
  "role_ids": ["uuid1", "uuid2"]
}
```

#### Audit Logs

##### List Audit Logs (Admin only)

```text
GET /api/v1/audit-logs
```

Query parameters:

- `user_id` (optional): Filter by user
- `application_id` (optional): Filter by application
- `action` (optional): Filter by action
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 50)

### Authentication Endpoints

#### Login

```text
POST /auth/login
```

Request body:

```json
{
  "username": "admin",
  "password": "password"
}
```

Response:

```json
{
  "token": "jwt_token_here",
  "user": {
    "id": "uuid",
    "username": "admin",
    "email": "admin@example.com",
    "roles": ["admin"],
    "is_admin": true
  }
}
```

#### Logout

```text
POST /auth/logout
```

#### Get Current User

```text
GET /auth/me
```

#### Refresh Token

```text
POST /auth/refresh
```

Request body:

```json
{
  "refresh_token": "refresh_token_here"
}
```

### Session Management

#### List Sessions

```text
GET /sessions
```

#### Revoke Session

```text
DELETE /sessions/:id
```

#### Revoke All Sessions

```text
DELETE /sessions
```

## OAuth 2.0 Implementation

OryxID implements the OAuth 2.0 and OpenID Connect specifications.

### Supported Flows

1. **Authorization Code Flow** (with PKCE support)
2. **Client Credentials Flow**
3. **Refresh Token Flow**
4. **Implicit Flow** (deprecated, not recommended)

### Authorization Endpoint

```text
GET /oauth/authorize
```

Parameters:

- `response_type`: `code` or `token`
- `client_id`: Application client ID
- `redirect_uri`: Registered redirect URI
- `scope`: Space-separated scopes
- `state`: CSRF protection state
- `nonce`: OpenID Connect nonce
- `code_challenge`: PKCE challenge
- `code_challenge_method`: `S256` or `plain`
- `audience`: API audience

### Token Endpoint

```text
POST /oauth/token
```

#### Authorization Code Grant

```bash
curl -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_HERE" \
  -d "redirect_uri=https://app.example.com/callback" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET" \
  -d "code_verifier=PKCE_VERIFIER"
```

#### Client Credentials Grant

```bash
curl -X POST https://auth.example.com/oauth/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=read:data write:data"
```

#### Refresh Token Grant

```bash
curl -X POST https://auth.example.com/oauth/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=REFRESH_TOKEN_HERE"
```

### Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "scope": "openid profile email"
}
```

### Token Introspection

```text
POST /oauth/introspect
```

Request:

```bash
curl -X POST https://auth.example.com/oauth/introspect \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=ACCESS_TOKEN_HERE"
```

Response:

```json
{
  "active": true,
  "scope": "read write",
  "client_id": "client_id",
  "username": "johndoe",
  "token_type": "Bearer",
  "exp": 1580000000,
  "iat": 1579996400,
  "sub": "user_uuid",
  "aud": "api_audience"
}
```

### Token Revocation

```text
POST /oauth/revoke
```

Request:

```bash
curl -X POST https://auth.example.com/oauth/revoke \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=TOKEN_HERE" \
  -d "token_type_hint=access_token"
```

### OpenID Connect Discovery

```text
GET /.well-known/openid-configuration
```

### JWKS Endpoint

```text
GET /.well-known/jwks.json
```

## Security Features

### 1. Password Security

- BCrypt hashing with configurable cost factor
- Minimum password requirements enforced
- Password history tracking (optional)

### 2. Token Security

- RS256 signed JWT tokens
- Short-lived access tokens (1 hour default)
- Long-lived refresh tokens (30 days default)
- Token revocation support
- Token introspection for validation

### 3. Rate Limiting

- Per-IP rate limiting
- Per-client rate limiting
- Adaptive rate limiting for repeat offenders
- Redis-based distributed rate limiting

### 4. CSRF Protection

- Double-submit cookie pattern
- CSRF tokens for state-changing operations
- Automatic token rotation

### 5. CORS Protection

- Configurable allowed origins
- Credentials support
- Preflight handling

### 6. Security Headers

- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- X-XSS-Protection: 1; mode=block
- Strict-Transport-Security (HSTS)
- Content-Security-Policy

### 7. PKCE Support

- Required for public clients
- S256 and plain methods supported
- Prevents authorization code interception

### 8. Audit Logging

- All authentication events logged
- Admin actions tracked
- Failed login attempts recorded
- IP address and user agent captured

## Database Schema

### Core Tables

#### users

- `id` (UUID, PK)
- `username` (string, unique)
- `email` (string, unique)
- `password` (string, bcrypt hash)
- `is_active` (boolean)
- `is_admin` (boolean)
- `created_at` (timestamp)
- `updated_at` (timestamp)

#### applications

- `id` (UUID, PK)
- `name` (string)
- `description` (text)
- `client_id` (string, unique)
- `client_secret` (string)
- `hashed_client_secret` (string)
- `client_type` (enum: confidential, public)
- `grant_types` (string[])
- `response_types` (string[])
- `redirect_uris` (string[])
- `skip_authorization` (boolean)
- `owner_id` (UUID, FK to users)
- `metadata` (JSONB)

#### scopes

- `id` (UUID, PK)
- `name` (string, unique)
- `description` (text)
- `is_default` (boolean)

#### authorization_codes

- `id` (UUID, PK)
- `code` (string, unique)
- `application_id` (UUID, FK)
- `user_id` (UUID, FK, nullable)
- `redirect_uri` (string)
- `scope` (string)
- `code_challenge` (string)
- `code_challenge_method` (string)
- `expires_at` (timestamp)
- `used` (boolean)

#### tokens

- `id` (UUID, PK)
- `token_hash` (string, unique)
- `token_type` (enum: access, refresh)
- `application_id` (UUID, FK)
- `user_id` (UUID, FK, nullable)
- `scope` (string)
- `audience` (string)
- `expires_at` (timestamp)
- `revoked` (boolean)
- `revoked_at` (timestamp, nullable)

#### sessions

- `id` (UUID, PK)
- `session_id` (string, unique)
- `user_id` (UUID, FK)
- `ip_address` (string)
- `user_agent` (string)
- `expires_at` (timestamp)
- `last_used` (timestamp)

#### audit_logs

- `id` (UUID, PK)
- `user_id` (UUID, FK, nullable)
- `application_id` (UUID, FK, nullable)
- `action` (string)
- `resource` (string)
- `resource_id` (string)
- `ip_address` (string)
- `user_agent` (string)
- `status_code` (integer)
- `metadata` (JSONB)
- `created_at` (timestamp)

### Relationships

- **users** ↔ **roles** (many-to-many)
- **roles** ↔ **permissions** (many-to-many)
- **applications** ↔ **scopes** (many-to-many)
- **applications** ↔ **audiences** (many-to-many)
- **audiences** ↔ **scopes** (many-to-many)

## Development Guide

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific package tests
go test ./internal/handlers

# Run tests with race detection
go test -race ./...
```

### Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Use `golangci-lint` for linting
- Write meaningful commit messages

### Adding New Endpoints

1. Define the handler in `internal/handlers/`
2. Add route in `cmd/server/main.go`
3. Update API documentation
4. Write tests for the handler
5. Add any necessary database migrations

### Database Migrations

```bash
# Create a new migration
go run cmd/migrate/main.go create add_new_table

# Run migrations
go run cmd/migrate/main.go up

# Rollback last migration
go run cmd/migrate/main.go down

# Check migration status
go run cmd/migrate/main.go status
```

## Production Deployment

### Deployment Prerequisites

1. PostgreSQL 12+ with SSL enabled
2. Redis 6+ with authentication
3. SSL certificates for HTTPS
4. Reverse proxy (nginx/traefik)

### Environment Setup

1. Set production environment variables:

   ```bash
   export ORYXID_SERVER_MODE=release
   export ORYXID_DATABASE_SSLMODE=require
   export ORYXID_OAUTH_ISSUER=https://auth.yourdomain.com
   export ORYXID_SECURITY_BCRYPTCOST=14
   ```

2. Use strong passwords and secrets:

   ```bash
   # Generate secure passwords
   openssl rand -base64 32
   ```

3. Configure proper CORS origins:

   ```bash
   export ORYXID_OAUTH_ALLOWEDORIGINS='["https://app.yourdomain.com"]'
   ```

### Building for Production

```bash
# Build binary
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-w -s -extldflags '-static'" \
  -o oryxid ./cmd/server

# Or use Docker
docker build -t oryxid:latest .
```

### Deployment Options

#### 1. Systemd Service

```ini
[Unit]
Description=OryxID OAuth Server
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=oryxid
Group=oryxid
WorkingDirectory=/opt/oryxid
ExecStart=/opt/oryxid/oryxid
Restart=always
RestartSec=5
Environment="ORYXID_SERVER_MODE=release"
EnvironmentFile=/opt/oryxid/.env

[Install]
WantedBy=multi-user.target
```

#### 2. Docker Compose

```yaml
version: "3.8"

services:
  oryxid:
    image: oryxid:latest
    environment:
      - ORYXID_SERVER_MODE=release
      - ORYXID_DATABASE_HOST=postgres
      - ORYXID_REDIS_HOST=redis
    depends_on:
      - postgres
      - redis
    ports:
      - "9000:9000"
    volumes:
      - ./certs:/app/certs:ro
    restart: unless-stopped
```

#### 3. Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oryxid
spec:
  replicas: 3
  selector:
    matchLabels:
      app: oryxid
  template:
    metadata:
      labels:
        app: oryxid
    spec:
      containers:
        - name: oryxid
          image: oryxid:latest
          ports:
            - containerPort: 9000
          env:
            - name: ORYXID_SERVER_MODE
              value: "release"
          envFrom:
            - secretRef:
                name: oryxid-secrets
          volumeMounts:
            - name: certs
              mountPath: /app/certs
              readOnly: true
      volumes:
        - name: certs
          secret:
            secretName: oryxid-certs
```

### Performance Tuning

1. **Database Connection Pool**

   ```yaml
   database:
   maxopenconns: 50
   maxidleconns: 10
   connmaxlifetime: 30m
   ```

2. **Redis Connection Pool**

   ```yaml
   redis:
   poolsize: 100
   minidleconns: 20
   ```

3. **Rate Limiting**

   ```yaml
   security:
   ratelimitrps: 1000
   ratelimitburst: 100
   ```

4. **HTTP Server**

   ```yaml
   server:
   readtimeout: 30s
   writetimeout: 30s
   ```

### Monitoring

1. **Health Check Endpoint**

   ```bash
   curl https://auth.yourdomain.com/health
   ```

2. **Metrics** (Prometheus format)

   ```bash
   curl https://auth.yourdomain.com/metrics
   ```

3. **Logging**

- Structured JSON logging in production
- Log aggregation with ELK/Loki
- Alert on error rates

### Security Checklist

- [ ] Use HTTPS everywhere
- [ ] Enable HSTS headers
- [ ] Configure firewall rules
- [ ] Enable database SSL
- [ ] Use strong passwords
- [ ] Rotate JWT signing keys
- [ ] Enable audit logging
- [ ] Configure rate limiting
- [ ] Set up monitoring/alerting
- [ ] Regular security updates
- [ ] Backup database regularly
- [ ] Test disaster recovery

## Troubleshooting

### Common Issues

#### 1. Database Connection Failed

**Error**: `failed to connect to database: dial tcp: connection refused`

**Solution**:

- Check PostgreSQL is running
- Verify connection parameters
- Check firewall rules
- Ensure PostgreSQL accepts connections

#### 2. Redis Connection Failed

**Error**: `failed to connect to Redis: dial tcp: connection refused`

**Solution**:

- Redis is optional, server continues without it
- Check Redis is running
- Verify Redis password
- Some features (distributed rate limiting) won't work

#### 3. JWT Key Loading Failed

**Error**: `failed to load JWT keys: no such file or directory`

**Solution**:

```bash
mkdir -p certs
openssl genrsa -out certs/private_key.pem 4096
openssl rsa -in certs/private_key.pem -pubout -out certs/public_key.pem
```

#### 4. Rate Limit Exceeded

**Error**: `{"error": "rate limit exceeded"}`

**Solution**:

- Wait before retrying
- Check rate limit configuration
- Consider increasing limits for specific clients

#### 5. CSRF Token Invalid

**Error**: `{"error": "csrf_token_invalid"}`

**Solution**:

- Ensure CSRF token is included in requests
- Check token hasn't expired
- Verify cookie settings

### Debug Mode

Enable debug mode for detailed logging:

```bash
export ORYXID_SERVER_MODE=debug
export GIN_MODE=debug
```
