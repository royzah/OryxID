# OryxID

OAuth2/OpenID Connect server with admin interface.

## Architecture

```mermaid
graph TB
    Client[Client Application]
    Browser[Web Browser]
    Nginx[Nginx Proxy :8080]
    Frontend[SvelteKit Frontend :3000]
    Backend[Go Backend :9000]
    DB[(PostgreSQL)]
    Redis[(Redis)]

    Browser --> Nginx
    Client --> Nginx
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

- Application: <http://localhost:8080>
- Backend API: <http://localhost:9000>
- Frontend Dev: <http://localhost:3000>

## OAuth2 Flows

```mermaid
sequenceDiagram
    participant Client
    participant Auth as OryxID
    participant Resource as Resource Server

    Note over Client,Resource: Authorization Code + PKCE

    Client->>Client: Generate code_verifier, code_challenge
    Client->>Auth: GET /oauth/authorize
    Auth->>Client: Authorization Code
    Client->>Auth: POST /oauth/token + code_verifier
    Auth->>Client: Access Token + Refresh Token
    Client->>Resource: Request + Bearer Token
    Resource->>Auth: Introspect Token
    Auth->>Resource: Token Valid
    Resource->>Client: Protected Resource
```

## Project Structure

```text
.
├── backend/          # Go API server
├── frontend/         # SvelteKit admin UI
├── docker/           # Docker configurations
├── certs/            # JWT signing keys
├── docker-compose.yml
├── Makefile
└── .env
```

See component documentation:

- [Backend README](./backend/README.md) - API, OAuth endpoints, configuration
- [Frontend README](./frontend/README.md) - Admin UI, components, development

## Creating OAuth Applications

### Via Admin Dashboard

1. Login at `http://localhost:8080` (default: admin/admin123)
2. Navigate to **Applications** in the sidebar
3. Click **Create Application**
4. Fill in the form:

   | Field | Description | Example |
   |-------|-------------|---------|
   | Name | Application display name | My App |
   | Client Type | `confidential` or `public` | confidential |
   | Redirect URIs | Callback URLs (one per line) | https://myapp.com/callback |
   | Grant Types | Allowed OAuth flows | client_credentials, authorization_code |
   | Scopes | Permissions requested | read, write |

5. Click **Create**
6. **Important**: Copy the **Client Secret** immediately - it's only shown once!

### Application Types

| Type | Use Case | Secret Required |
|------|----------|-----------------|
| confidential | Server-side apps | Yes |
| public | SPAs, mobile apps | No |

### Grant Types

| Grant | Use Case |
|-------|----------|
| client_credentials | Machine-to-machine |
| authorization_code | User login flows |
| refresh_token | Token refresh |

### Testing OAuth Credentials

Use the included Python script to verify your client credentials:

```bash
# Test client_credentials flow
python scripts/test_oauth_client.py \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_SECRET \
  --url http://localhost:9000

# With custom scope
python scripts/test_oauth_client.py \
  -c YOUR_CLIENT_ID \
  -s YOUR_SECRET \
  --scope "read write"
```

Expected output for valid credentials:

```text
Testing OAuth client credentials against http://localhost:9000
Client ID: YOUR_CLIENT_ID
--------------------------------------------------

[1] Testing client_credentials grant...
    Status: SUCCESS
    Access Token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
    Token Type: Bearer
    Expires In: 3600 seconds
    Scope: read

[2] Testing token introspection...
    Status: SUCCESS
    Active: True
    Client ID: YOUR_CLIENT_ID
    Scope: read

==================================================
RESULT: Client credentials are VALID
==================================================
```

## Security Features

### OAuth 2.1 Compliance

- PKCE with S256 (plain method rejected)
- Refresh token rotation
- Access token revocation
- No implicit flow

### OpenID Connect 1.0

- ID tokens with required claims
- UserInfo endpoint
- Discovery endpoint `/.well-known/openid-configuration`
- JWKS endpoint `/.well-known/jwks.json`

### Additional Security

- PAR (Pushed Authorization Requests)
- private_key_jwt client authentication
- Rate limiting
- CSRF protection

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
make db-backup       # Backup database
make db-restore      # Restore backup

# Maintenance
make build           # Build images
make clean           # Remove containers
make logs            # View logs
```

Run `make help` for full command list.

## Configuration

Copy `.env.example` to `.env` and configure:

| Variable | Description | Default |
|----------|-------------|---------|
| DB_USER | PostgreSQL user | oryxid |
| DB_PASSWORD | PostgreSQL password | - |
| DB_NAME | Database name | oryxid |
| REDIS_PASSWORD | Redis password | - |
| ADMIN_USERNAME | Admin user | admin |
| ADMIN_PASSWORD | Admin password | - |
| OAUTH_ISSUER | Token issuer URL | <http://localhost:8080> |

## Deployment

### Docker Compose (Development/Staging)

```bash
make prod-build
make prod-up
```

### Cloud Deployment

```mermaid
graph TB
    LB[Load Balancer]
    CDN[CDN]

    subgraph Compute
        App1[OryxID 1]
        App2[OryxID 2]
        AppN[OryxID N]
    end

    subgraph Data
        RDS[(Managed PostgreSQL)]
        Cache[(Managed Redis)]
    end

    LB --> CDN
    CDN --> App1
    CDN --> App2
    CDN --> AppN

    App1 & App2 & AppN --> RDS
    App1 & App2 & AppN --> Cache
```

**AWS**: ECS Fargate or EKS
**GCP**: Cloud Run or GKE
**Azure**: Container Instances or AKS

### Environment Variables (Production)

```bash
DATABASE_URL=postgresql://user:pass@host:5432/oryxid
REDIS_URL=redis://host:6379
JWT_PRIVATE_KEY_PATH=/app/certs/private_key.pem
JWT_PUBLIC_KEY_PATH=/app/certs/public_key.pem
BASE_URL=https://auth.yourdomain.com
```

## License

MIT
