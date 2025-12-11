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

---

## Concepts Guide

This section explains OAuth 2.0 / OIDC concepts for administrators and developers.

### What is OAuth 2.0?

OAuth 2.0 is an authorization framework that allows applications to obtain limited access to user accounts on third-party services. Instead of sharing passwords, users authorize applications to act on their behalf.

```mermaid
graph LR
    User[Resource Owner]
    Client[Client Application]
    Auth[Authorization Server<br/>OryxID]
    Resource[Resource Server]

    User -->|1. Authorizes| Client
    Client -->|2. Requests Token| Auth
    Auth -->|3. Issues Token| Client
    Client -->|4. Uses Token| Resource
    Resource -->|5. Returns Data| Client
```

### Scopes

Scopes define the specific permissions an application is requesting. They limit what an access token can do.

#### What Scopes Do

| Scope | Purpose | Access Level |
|-------|---------|--------------|
| `openid` | Required for OIDC - returns ID token with user identity | Identity |
| `profile` | Access to user's name, picture, locale | User Info |
| `email` | Access to user's email address | User Info |
| `offline_access` | Request refresh tokens for long-lived access | Token |
| `read` | Read-only access to resources | Resource |
| `write` | Write/modify access to resources | Resource |

#### Scope Flow

```mermaid
sequenceDiagram
    participant Client
    participant Auth as OryxID
    participant User
    participant API as Resource API

    Client->>Auth: Request scope=openid email read
    Auth->>User: Show consent screen
    Note over User: "App requests:<br/>- Your identity<br/>- Your email<br/>- Read your data"
    User->>Auth: Approve
    Auth->>Client: Token with scopes: openid email read
    Client->>API: GET /data (Bearer token)
    API->>API: Check token has 'read' scope
    API->>Client: Return data
    Client->>API: POST /data (Bearer token)
    API->>API: Check token - no 'write' scope
    API->>Client: 403 Forbidden
```

#### Creating Custom Scopes

Define scopes that match your API's permission model:

| Custom Scope | Use Case |
|--------------|----------|
| `users:read` | Read user profiles |
| `users:write` | Create/modify users |
| `orders:create` | Create new orders |
| `admin` | Administrative access |

#### Default Scopes

When "Include by default" is enabled, the scope is automatically granted to all applications without explicit request. Use sparingly for essential scopes like `openid`.

---

### Client Types

OAuth defines two client types based on their ability to maintain credential confidentiality.

#### Confidential vs Public

```mermaid
graph TB
    subgraph Confidential
        Server[Server-side App]
        Backend[Backend Service]
        API[API Client]
    end

    subgraph Public
        SPA[Browser SPA]
        Mobile[Mobile App]
        CLI[CLI Tool]
        Desktop[Desktop App]
    end

    Server -->|Secure Storage| Secret[Client Secret]
    Backend -->|Secure Storage| Secret
    API -->|Secure Storage| Secret

    SPA -->|Cannot Hide| NoSecret[No Secret]
    Mobile -->|Cannot Hide| NoSecret
    CLI -->|Cannot Hide| NoSecret
    Desktop -->|Cannot Hide| NoSecret
```

| Type | Can Store Secret | Examples | Authentication |
|------|------------------|----------|----------------|
| **Confidential** | Yes | Server apps, backend services, secure APIs | client_secret_basic, client_secret_post, private_key_jwt |
| **Public** | No | SPAs, mobile apps, desktop apps, CLI tools | PKCE only (no secret) |

#### Why This Matters

```mermaid
flowchart TD
    A[Client Type?] -->|Confidential| B[Can use client_secret]
    A -->|Public| C[Must use PKCE]

    B --> D[Server validates secret]
    C --> E[Server validates code_verifier]

    D --> F[Token issued]
    E --> F
```

**Security Implications:**

- **Confidential clients**: Secret never leaves secure server. Server verifies both the secret and the authorization code.
- **Public clients**: No secret to steal. PKCE ensures only the app that started the flow can complete it.

#### When to Choose Each

| Scenario | Client Type | Reason |
|----------|-------------|--------|
| Node.js/Python/Go backend | Confidential | Secret stored securely on server |
| React/Vue/Angular SPA | Public | JavaScript is viewable in browser |
| iOS/Android app | Public | Binary can be reverse-engineered |
| CLI tool | Public | Users have access to source/config |
| Microservice-to-microservice | Confidential | Both services are server-side |

---

### Grant Types

Grant types define how an application obtains tokens. Choose based on your application type and user interaction model.

#### Grant Type Decision Tree

```mermaid
flowchart TD
    A[Start] --> B{User present?}

    B -->|Yes| C{User can interact<br/>with browser?}
    B -->|No| D{Machine-to-machine?}

    C -->|Yes| E[Authorization Code + PKCE]
    C -->|No - limited device| F{User has separate<br/>device with browser?}

    F -->|Yes| G[Device Authorization]
    F -->|No| H[CIBA]

    D -->|Yes| I[Client Credentials]
    D -->|No| J{Token delegation?}

    J -->|Yes| K[Token Exchange]
    J -->|No| L[Evaluate use case]
```

#### Grant Type Comparison

| Grant Type | User Present | Browser Required | Use Case |
|------------|--------------|------------------|----------|
| Authorization Code + PKCE | Yes | Yes | Web apps, mobile apps, SPAs |
| Client Credentials | No | No | Server-to-server API calls |
| Device Authorization | Yes | Separate device | Smart TVs, CLI tools, IoT |
| Token Exchange | No | No | Microservice delegation |
| CIBA | Yes | No | Call centers, POS systems |
| Refresh Token | N/A | No | Token renewal |
| Implicit | Yes | Yes | DEPRECATED - Do not use |

#### Combining Grant Types

Applications typically enable multiple grant types:

```mermaid
graph LR
    subgraph Web Application
        AC[Authorization Code]
        RT[Refresh Token]
    end

    subgraph Backend Service
        CC[Client Credentials]
    end

    subgraph Mobile App
        AC2[Authorization Code]
        RT2[Refresh Token]
        DC[Device Code<br/>for TV companion]
    end

    subgraph Microservices
        CC2[Client Credentials]
        TE[Token Exchange]
    end
```

**Common Combinations:**

| Application Type | Recommended Grant Types |
|------------------|------------------------|
| Web Application | authorization_code, refresh_token |
| SPA (Single Page App) | authorization_code (PKCE required) |
| Mobile App | authorization_code, refresh_token |
| Backend Service | client_credentials |
| Microservice Gateway | client_credentials, token-exchange |
| Smart TV App | device_code, refresh_token |
| CLI Tool | device_code |
| IoT Device | device_code, client_credentials |

#### Detailed Grant Type Explanations

##### Authorization Code (with PKCE)

The most secure flow for applications with user interaction.

```mermaid
sequenceDiagram
    participant App as Application
    participant Browser
    participant Auth as OryxID
    participant API

    App->>App: Generate code_verifier (random)
    App->>App: code_challenge = SHA256(code_verifier)
    App->>Browser: Redirect to /oauth/authorize
    Browser->>Auth: GET /authorize?code_challenge=...
    Auth->>Browser: Login page
    Browser->>Auth: User credentials
    Auth->>Browser: Consent page
    Browser->>Auth: User approves
    Auth->>Browser: Redirect with ?code=abc123
    Browser->>App: Authorization code
    App->>Auth: POST /token + code + code_verifier
    Auth->>Auth: Verify SHA256(code_verifier) == code_challenge
    Auth->>App: access_token, refresh_token, id_token
    App->>API: Request with Bearer token
```

**PKCE (Proof Key for Code Exchange):**
- Prevents authorization code interception attacks
- Required for all public clients
- Recommended for confidential clients (OAuth 2.1)

##### Client Credentials

For server-to-server communication without user context.

```mermaid
sequenceDiagram
    participant Service as Backend Service
    participant Auth as OryxID
    participant API as Target API

    Service->>Auth: POST /token
    Note over Service,Auth: grant_type=client_credentials<br/>client_id + client_secret<br/>scope=api:read
    Auth->>Auth: Validate credentials
    Auth->>Service: access_token (no user context)
    Service->>API: Request + Bearer token
    API->>Service: Response
```

**Characteristics:**
- No user involved - token represents the application itself
- No refresh tokens (just request new token when expired)
- Short-lived tokens recommended

##### Device Authorization (RFC 8628)

For devices that cannot display a browser or have limited input.

```mermaid
sequenceDiagram
    participant Device as Smart TV
    participant Phone as User's Phone
    participant Auth as OryxID

    Device->>Auth: POST /device_authorization
    Auth->>Device: device_code, user_code: "WDJB-MJHT"

    Device->>Device: Display: "Visit oryxid.com/device<br/>Enter: WDJB-MJHT"

    loop Every 5 seconds
        Device->>Auth: POST /token (device_code)
        Auth->>Device: authorization_pending
    end

    Phone->>Auth: Visit /device
    Phone->>Auth: Enter code "WDJB-MJHT"
    Auth->>Phone: Consent screen
    Phone->>Auth: Approve

    Device->>Auth: POST /token (device_code)
    Auth->>Device: access_token, refresh_token
```

##### Token Exchange (RFC 8693)

Exchange one token for another with different characteristics.

```mermaid
sequenceDiagram
    participant Frontend
    participant Gateway as API Gateway
    participant Auth as OryxID
    participant Service as Internal Service

    Frontend->>Gateway: Request + user_token
    Gateway->>Auth: POST /token
    Note over Gateway,Auth: grant_type=token-exchange<br/>subject_token=user_token<br/>audience=internal-service
    Auth->>Auth: Validate user_token
    Auth->>Auth: Issue scoped token
    Auth->>Gateway: service_token (narrower scope)
    Gateway->>Service: Request + service_token
    Service->>Gateway: Response
    Gateway->>Frontend: Response
```

**Use Cases:**
- **Delegation**: Service A calls Service B on behalf of user
- **Impersonation**: Admin acts as another user
- **Scope reduction**: Narrow token scope for specific service

##### CIBA (Client-Initiated Backchannel Authentication)

Authenticate users without redirecting them.

```mermaid
sequenceDiagram
    participant Operator as Call Center
    participant Auth as OryxID
    participant App as User's Phone App
    participant User

    Operator->>Auth: POST /bc-authorize (login_hint=user@email.com)
    Auth->>Operator: auth_req_id

    Auth->>App: Push notification
    App->>User: "Call center requests access"
    User->>App: Approve
    App->>Auth: Confirm authorization

    loop Poll
        Operator->>Auth: POST /token (auth_req_id)
    end
    Auth->>Operator: access_token
```

**Use Cases:**
- Call centers verifying customer identity
- Point-of-sale systems
- Kiosk applications

##### Implicit (DEPRECATED)

```mermaid
graph LR
    A[Implicit Grant] -->|Security Issues| B[Token in URL fragment]
    B --> C[Exposed in browser history]
    B --> D[Exposed in referrer headers]
    B --> E[No refresh tokens]

    F[Use Instead] --> G[Authorization Code + PKCE]
```

**Why Deprecated:**
- Access token exposed in URL (browser history, logs, referrer)
- No way to verify the recipient
- No refresh tokens possible
- Replaced by Authorization Code + PKCE which is secure for public clients

---

### Redirect URIs

Redirect URIs are where OryxID sends the user after authorization.

#### How Redirect URIs Work

```mermaid
sequenceDiagram
    participant App
    participant Browser
    participant Auth as OryxID

    App->>Browser: Redirect to /authorize<br/>redirect_uri=https://app.com/callback
    Browser->>Auth: Authorization request
    Auth->>Auth: Verify redirect_uri matches registered URIs
    Auth->>Browser: Redirect to https://app.com/callback?code=xyz
    Browser->>App: Code delivered to callback
```

#### Security Requirements

| Rule | Reason |
|------|--------|
| Must be pre-registered | Prevents open redirector attacks |
| Exact match required | No partial matching |
| HTTPS required (production) | Prevents token interception |
| No wildcards | Each URI explicitly listed |

#### Examples by Application Type

| Application Type | Example Redirect URIs |
|------------------|----------------------|
| Web application | `https://myapp.com/auth/callback` |
| Development | `http://localhost:3000/callback` |
| Mobile (iOS) | `com.myapp.auth://callback` |
| Mobile (Android) | `com.myapp://oauth/redirect` |
| Desktop | `http://localhost:8765/callback` |
| CLI tool | `http://127.0.0.1:9999/callback` |

#### Multiple Redirect URIs

Register all environments your app uses:

```
https://myapp.com/callback          # Production
https://staging.myapp.com/callback  # Staging
http://localhost:3000/callback      # Development
```

---

### Skip Authorization Prompt

When enabled, users are not shown the consent screen.

#### Normal Flow (Skip Disabled)

```mermaid
sequenceDiagram
    participant User
    participant Auth as OryxID

    User->>Auth: Login
    Auth->>User: Consent Screen
    Note over User: "App wants to:<br/>- Access your profile<br/>- Read your email"
    User->>Auth: Approve
    Auth->>User: Redirect with code
```

#### First-Party Flow (Skip Enabled)

```mermaid
sequenceDiagram
    participant User
    participant Auth as OryxID

    User->>Auth: Login
    Auth->>User: Redirect with code
    Note over Auth: No consent screen shown
```

#### When to Use

| Scenario | Skip Authorization | Reason |
|----------|-------------------|--------|
| Third-party app | No | User must consent to data sharing |
| Your own frontend | Yes | User trusts your app implicitly |
| Partner integration | No | User should know what's shared |
| Internal admin tool | Yes | Internal users, implicit trust |
| Mobile app for your service | Yes | First-party application |

**Security Note:** Only enable for applications you fully control. Third-party applications should always show consent to users.

---

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

---

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

---

## Creating OAuth Applications

### Via Admin Dashboard

1. Login at `http://localhost:8080` (default: admin/admin123)
2. Navigate to **Applications**
3. Click **New Application**
4. Configure the fields (see table below)
5. Save and copy the **Client Secret** (shown only once)

### Configuration Fields

| Field | Description | Required |
|-------|-------------|----------|
| Name | Display name for the application | Yes |
| Description | What the application does | No |
| Client Type | `confidential` or `public` (see above) | Yes |
| Grant Types | Which OAuth flows are allowed | Yes |
| Redirect URIs | Where to send users after auth | Yes |
| Scopes | What permissions the app can request | Yes |
| Skip Authorization | Skip consent for first-party apps | No |

---

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

---

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

---

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

---

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

---

## Testing

### Run Tests

```bash
# Backend unit tests
cd backend && go test ./...

# Backend with coverage
cd backend && go test -coverprofile=coverage.out ./...

# Frontend tests
cd frontend && npm test

# Integration tests (requires running server)
TEST_CLIENT_ID=your-client-id \
TEST_CLIENT_SECRET=your-secret \
API_URL=http://localhost:9000 \
go test ./tests/integration/... -v
```

### Test OAuth Flows

```bash
# Client credentials
curl -X POST http://localhost:8080/oauth/token \
  -u "client_id:client_secret" \
  -d "grant_type=client_credentials&scope=openid"

# Device authorization
curl -X POST http://localhost:8080/oauth/device_authorization \
  -d "client_id=YOUR_CLIENT_ID&scope=openid"
```

---

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

---

## License

MIT
