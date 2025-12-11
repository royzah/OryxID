# OryxID

OAuth 2.0 / OpenID Connect Authorization Server with comprehensive protocol support.

## Features

- OAuth 2.0 and OpenID Connect 1.0 compliant
- Authorization Code Flow with PKCE
- Client Credentials Grant
- Refresh Token Grant with rotation
- Device Authorization Grant (RFC 8628)
- Token Exchange (RFC 8693)
- CIBA - Client-Initiated Backchannel Authentication
- Rich Authorization Requests (RFC 9396)
- Pushed Authorization Requests (RFC 9126)
- Token Introspection (RFC 7662)
- Token Revocation (RFC 7009)

## Architecture

```mermaid
graph TB
    Client[Client Application]
    Browser[Web Browser]
    Device[Limited Input Device]
    Nginx[Nginx Proxy :8080]
    Frontend[SvelteKit Frontend :3000]
    Backend[Go Backend :9000]
    DB[(PostgreSQL)]
    Redis[(Redis)]

    Browser --> Nginx
    Client --> Nginx
    Device --> Nginx
    Nginx --> Frontend
    Nginx --> Backend
    Backend --> DB
    Backend --> Redis
    Frontend -.->|API| Backend

    style Nginx fill:#4CAF50
    style Backend fill:#00ADD8
    style Frontend fill:#FF3E00
    style DB fill:#336791
    style Redis fill:#DC382D
```

## Quick Start

```bash
# Setup (first time only)
make setup

# Start all services
make up

# Check status
make status
```

Access points:
- Application: http://localhost:8080
- Backend API: http://localhost:9000
- Frontend Dev: http://localhost:3000

## OAuth 2.0 Flows

### Authorization Code Flow with PKCE

```mermaid
sequenceDiagram
    participant Client
    participant User as User Browser
    participant Auth as OryxID
    participant Resource as Resource Server

    Client->>Client: Generate code_verifier, code_challenge
    Client->>User: Redirect to /oauth/authorize
    User->>Auth: GET /oauth/authorize?code_challenge=...
    Auth->>User: Login Page
    User->>Auth: Credentials
    Auth->>User: Consent Page
    User->>Auth: Approve
    Auth->>User: Redirect with code
    User->>Client: code
    Client->>Auth: POST /oauth/token + code_verifier
    Auth->>Auth: Verify PKCE
    Auth->>Client: access_token, refresh_token, id_token
    Client->>Resource: Request + Bearer Token
    Resource->>Auth: POST /oauth/introspect
    Auth->>Resource: active: true
    Resource->>Client: Protected Resource
```

### Client Credentials Flow

```mermaid
sequenceDiagram
    participant Client as Client (Server)
    participant Auth as OryxID
    participant Resource as Resource Server

    Client->>Auth: POST /oauth/token
    Note over Client,Auth: grant_type=client_credentials<br/>client_id + client_secret
    Auth->>Auth: Validate credentials
    Auth->>Client: access_token
    Client->>Resource: Request + Bearer Token
    Resource->>Client: Protected Resource
```

### Device Authorization Flow (RFC 8628)

For devices with limited input capabilities (TVs, CLI tools, IoT).

```mermaid
sequenceDiagram
    participant Device as Limited Device
    participant User as User Browser
    participant Auth as OryxID

    Device->>Auth: POST /oauth/device_authorization
    Note over Device,Auth: client_id, scope
    Auth->>Device: device_code, user_code, verification_uri

    Device->>User: Display user_code and URI
    Note over Device: Shows: "Go to example.com/device<br/>Enter code: WDJB-MJHT"

    loop Poll every 5 seconds
        Device->>Auth: POST /oauth/token
        Note over Device,Auth: grant_type=device_code<br/>device_code=...
        Auth->>Device: authorization_pending
    end

    User->>Auth: Visit /device
    User->>Auth: Enter user_code
    Auth->>User: Consent prompt
    User->>Auth: Approve

    Device->>Auth: POST /oauth/token
    Auth->>Device: access_token, refresh_token
```

### Token Exchange (RFC 8693)

Exchange tokens for delegation, impersonation, or format conversion.

```mermaid
sequenceDiagram
    participant Client as Frontend Client
    participant API as API Gateway
    participant Auth as OryxID
    participant Backend as Backend Service

    Client->>API: Request + access_token
    API->>Auth: POST /oauth/token
    Note over API,Auth: grant_type=token-exchange<br/>subject_token=client_token<br/>audience=backend-service
    Auth->>Auth: Validate subject_token
    Auth->>Auth: Generate scoped token
    Auth->>API: new_access_token (scoped to backend)
    API->>Backend: Request + new_access_token
    Backend->>API: Response
    API->>Client: Response
```

Token Exchange Types:
- **Delegation**: Exchange token for same user, different audience
- **Impersonation**: Exchange token with actor_token for audit trail
- **Scope Reduction**: Exchange token for narrower scope

### CIBA - Backchannel Authentication

Authenticate users on a separate device without redirect.

```mermaid
sequenceDiagram
    participant Client as Client App
    participant Auth as OryxID
    participant Device as User Device
    participant User

    Client->>Auth: POST /oauth/bc-authorize
    Note over Client,Auth: login_hint=user@example.com<br/>scope=openid<br/>binding_message="Login to App"
    Auth->>Client: auth_req_id, interval

    Auth->>Device: Push notification
    Device->>User: "App wants to sign in"
    User->>Device: Approve
    Device->>Auth: POST /oauth/bc-authorize/complete

    loop Poll
        Client->>Auth: POST /oauth/token
        Note over Client,Auth: grant_type=ciba<br/>auth_req_id=...
    end

    Auth->>Client: access_token, id_token
```

### Rich Authorization Requests (RFC 9396)

Fine-grained authorization with structured authorization_details.

```mermaid
sequenceDiagram
    participant Client
    participant Auth as OryxID
    participant User

    Client->>Auth: POST /oauth/par
    Note over Client,Auth: authorization_details=[<br/>  {"type":"payment",<br/>   "amount":"100.00",<br/>   "currency":"EUR"}<br/>]
    Auth->>Client: request_uri

    Client->>User: Redirect to /oauth/authorize?request_uri=...
    User->>Auth: Visit authorize endpoint
    Auth->>User: Show detailed consent
    Note over User: "App wants to:<br/>- Make payment: EUR 100.00"
    User->>Auth: Approve

    Auth->>Client: code
    Client->>Auth: POST /oauth/token
    Auth->>Client: access_token + authorization_details
```

## Discovery and JWKS

### OpenID Connect Discovery

```
GET /.well-known/openid-configuration
```

Returns server metadata:
- Supported grant types
- Supported scopes
- Token endpoint authentication methods
- JWKS URI
- All supported OAuth 2.0 / OIDC features

### JWKS (JSON Web Key Set)

```
GET /.well-known/jwks.json
```

Returns public keys for token verification.

## Endpoints Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/oauth/authorize` | GET | Authorization endpoint |
| `/oauth/token` | POST | Token endpoint |
| `/oauth/introspect` | POST | Token introspection |
| `/oauth/revoke` | POST | Token revocation |
| `/oauth/par` | POST | Pushed Authorization Request |
| `/oauth/device_authorization` | POST | Device authorization |
| `/oauth/bc-authorize` | POST | CIBA initiation |
| `/oauth/userinfo` | GET/POST | UserInfo endpoint |
| `/.well-known/openid-configuration` | GET | Discovery |
| `/.well-known/jwks.json` | GET | JWKS |

## Grant Types

| Grant Type | Use Case | RFC |
|------------|----------|-----|
| `authorization_code` | Web/mobile apps with user interaction | RFC 6749 |
| `client_credentials` | Server-to-server | RFC 6749 |
| `refresh_token` | Token renewal | RFC 6749 |
| `urn:ietf:params:oauth:grant-type:device_code` | Devices with limited input | RFC 8628 |
| `urn:ietf:params:oauth:grant-type:token-exchange` | Token delegation/impersonation | RFC 8693 |
| `urn:ietf:params:oauth:grant-type:ciba` | Backchannel authentication | OIDC CIBA |

## Project Structure

```
.
├── backend/              # Go API server
│   ├── cmd/              # Application entrypoint
│   ├── internal/
│   │   ├── oauth/        # OAuth 2.0 / OIDC implementation
│   │   ├── handlers/     # HTTP handlers
│   │   ├── database/     # Database models
│   │   ├── tokens/       # JWT generation/validation
│   │   └── middleware/   # HTTP middleware
│   └── tests/            # Integration tests
├── frontend/             # SvelteKit admin UI
│   ├── src/
│   │   ├── routes/       # Pages and layouts
│   │   │   ├── applications/  # OAuth app management
│   │   │   ├── device/        # Device authorization UI
│   │   │   ├── authorize/     # User consent UI
│   │   │   └── ...
│   │   ├── lib/
│   │   │   ├── api/      # API client
│   │   │   ├── stores/   # State management
│   │   │   └── components/
│   │   └── ...
│   └── ...
├── docker/               # Docker configurations
├── certs/                # JWT signing keys
├── docker-compose.yml
├── Makefile
└── .env
```

## Creating OAuth Applications

### Via Admin Dashboard

1. Login at `http://localhost:8080` (default: admin/admin123)
2. Navigate to **Applications**
3. Click **New Application**
4. Configure:

| Field | Description |
|-------|-------------|
| Name | Application display name |
| Client Type | `confidential` or `public` |
| Grant Types | Select enabled flows |
| Redirect URIs | Callback URLs |
| Scopes | Allowed permissions |

5. Save and copy the **Client Secret** (shown only once)

### Application Types

| Type | Description | Use Case |
|------|-------------|----------|
| confidential | Can securely store credentials | Server-side apps |
| public | Cannot securely store credentials | SPAs, mobile, CLI |

## Security Features

### OAuth 2.1 Compliance

- PKCE required for authorization code flow (S256 only)
- Refresh token rotation with revocation
- No implicit grant
- Strict redirect URI validation

### Client Authentication Methods

| Method | Description |
|--------|-------------|
| `client_secret_basic` | HTTP Basic Auth header |
| `client_secret_post` | Credentials in request body |
| `private_key_jwt` | JWT signed with client private key |
| `none` | Public clients (with PKCE) |

### Token Security

- Short-lived access tokens (1 hour default)
- Long-lived refresh tokens with rotation
- Refresh token reuse detection
- Token binding to client

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | - |
| `REDIS_URL` | Redis connection string | - |
| `OAUTH_ISSUER` | Token issuer URL | http://localhost:8080 |
| `ACCESS_TOKEN_LIFETIME` | Access token TTL (seconds) | 3600 |
| `REFRESH_TOKEN_LIFETIME` | Refresh token TTL (seconds) | 2592000 |
| `AUTH_CODE_LIFETIME` | Authorization code TTL (seconds) | 600 |
| `DEVICE_CODE_LIFETIME` | Device code TTL (seconds) | 1800 |
| `CIBA_POLL_INTERVAL` | CIBA polling interval (seconds) | 5 |

## Make Commands

```bash
# Lifecycle
make up              # Start services
make down            # Stop services
make restart         # Restart services
make status          # Health check

# Development
make dev             # Development mode
make dev-backend     # Backend only
make dev-frontend    # Frontend only

# Testing
make test            # All tests
make test-backend    # Backend tests
make test-frontend   # Frontend tests
make test-coverage   # Coverage report

# Database
make db-shell        # PostgreSQL shell
make db-migrate      # Run migrations
make db-seed         # Seed test data

# Maintenance
make build           # Build images
make clean           # Remove containers
make logs            # View logs
```

## Deployment

### Docker Compose

```bash
make prod-build
make prod-up
```

### Cloud Architecture

```mermaid
graph TB
    LB[Load Balancer]
    CDN[CDN / WAF]

    subgraph Compute
        App1[OryxID Pod 1]
        App2[OryxID Pod 2]
        AppN[OryxID Pod N]
    end

    subgraph Data
        Primary[(PostgreSQL Primary)]
        Replica[(PostgreSQL Replica)]
        Cache[(Redis Cluster)]
    end

    LB --> CDN
    CDN --> App1
    CDN --> App2
    CDN --> AppN

    App1 & App2 & AppN --> Primary
    Primary --> Replica
    App1 & App2 & AppN --> Cache
```

### Production Environment

```bash
DATABASE_URL=postgresql://user:pass@host:5432/oryxid?sslmode=require
REDIS_URL=rediss://host:6379
JWT_PRIVATE_KEY_PATH=/secrets/private_key.pem
JWT_PUBLIC_KEY_PATH=/secrets/public_key.pem
BASE_URL=https://auth.yourdomain.com
```

## Testing

Run tests:

```bash
# Backend unit tests
cd backend && go test ./...

# Backend with coverage
cd backend && go test -coverprofile=coverage.out ./...

# Frontend tests
cd frontend && npm test
```

Test OAuth flows:

```bash
# Client credentials
curl -X POST http://localhost:8080/oauth/token \
  -u "client_id:client_secret" \
  -d "grant_type=client_credentials&scope=openid"

# Device authorization
curl -X POST http://localhost:8080/oauth/device_authorization \
  -d "client_id=YOUR_CLIENT_ID&scope=openid"
```

## License

MIT
