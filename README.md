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
