# OryxID Roadmap

## Mission

Lightweight OAuth 2.1 authorization server for securing internal APIs with scope-based access control.

```mermaid
flowchart LR
    Client -->|client_credentials| OryxID
    OryxID -->|JWT + scopes| Client
    Client -->|Bearer token| API
    API -->|validate| OryxID
```

---

## Phase 1: API Security Foundation

Core features for securing APIs with tokens and scopes.

```mermaid
flowchart TD
    A[Token Validation SDK] --> B[Scope Hierarchy]
    B --> C[API Resource Registry]
    C --> D[Client Management]
```

### Token Validation SDK

- [x] Go middleware package for API servers
- [x] JWT validation with JWKS caching
- [x] Token introspection client
- [x] Scope enforcement helpers
- [x] Example integration code

### Scope Hierarchy

- [x] Wildcard scopes (billing:* grants billing:read, billing:write)
- [x] Scope inheritance model
- [x] Scope validation with hierarchy

### API Resource Registry

- [x] Register API resources in admin
- [x] Map scopes to API resources
- [x] Resource-based token audience

### Client Management

- [x] Client credentials rotation
- [x] Client scope restrictions
- [x] Client rate limiting
- [x] Client activity logs

---

## Phase 2: Operational Readiness

Production operations and observability.

```mermaid
flowchart TD
    A[Metrics] --> B[Documentation]
    B --> C[Health Monitoring]
```

### Metrics

- [x] Token issuance counter (by client, grant type)
- [x] Token validation latency
- [x] Failed authentication counter
- [x] Rate limit violations
- [x] Active tokens gauge

### Documentation

- [x] M2M integration guide
- [x] API security patterns (in M2M guide)
- [x] Scope design guidelines (in M2M guide)
- [x] OpenAPI specification

### Health Monitoring

- [x] Detailed health endpoints
- [x] Dependency health (database, redis)
- [x] Alerting integration

---

## Phase 3: Admin Security

Secure the admin interface and operators.

```mermaid
flowchart TD
    A[Account Lockout] --> B[Password Policy]
    B --> C[Audit Enhancement]
```

### Account Lockout

- [ ] Lockout after failed attempts
- [ ] Configurable threshold
- [ ] Admin unlock capability

### Password Policy

- [ ] Minimum length (12+)
- [ ] Complexity requirements
- [ ] Password expiration

### Audit Enhancement

- [ ] Client credential usage logs
- [ ] Scope grant audit trail
- [ ] Admin action logs

---

## Phase 4: Advanced Token Features

Enhanced token capabilities.

```mermaid
flowchart TD
    A[Token Binding] --> B[Custom Claims]
    B --> C[Token Analytics]
```

### Token Binding

- [x] DPoP (Demonstrating Proof of Possession) - RFC 9449
- [ ] Client certificate binding (mTLS)

### Custom Claims

- [ ] Custom claim configuration per client
- [ ] Claim transformations
- [ ] External claim sources

### Token Analytics

- [ ] Token usage dashboard
- [ ] Client activity reports
- [ ] Scope usage statistics

---

## Phase 5: Extended Use Cases

Additional flows when needed.

```mermaid
flowchart TD
    A[User Authentication] --> B[External Identity]
```

### User Authentication

- [ ] Authorization Code flow improvements
- [ ] Session management
- [ ] User consent UI

### External Identity

- [ ] LDAP connector
- [ ] OIDC federation
- [ ] Social login

---

## Out of Scope

Not needed for M2M API security:

- Self-registration
- Password reset flow
- Email integration
- WebAuthn/Passkeys

---

## Completed

### OAuth 2.1 Core

- [x] Authorization Code with PKCE
- [x] Client Credentials
- [x] Refresh Token with rotation
- [x] Token Introspection (RFC 7662)
- [x] Token Revocation (RFC 7009)

### Token Infrastructure

- [x] OIDC Discovery endpoint
- [x] JWKS endpoint
- [x] JWT signing (RS256)
- [x] Configurable token expiry

### Scope and Audience

- [x] Scope CRUD in admin
- [x] Audience CRUD in admin
- [x] Scope validation on token request
- [x] Audience in token claims

### Security

- [x] PKCE enforcement (S256)
- [x] Client secret hashing
- [x] Rate limiting
- [x] CSRF protection
- [x] Security headers
- [x] TLS support

### Admin

- [x] Admin dashboard
- [x] Application management
- [x] User management
- [x] Scope management
- [x] Audience management
- [x] Audit logging

### Infrastructure

- [x] Docker support
- [x] Kubernetes Helm chart
- [x] PostgreSQL support
- [x] Redis integration
- [x] Health endpoint

### CI/CD

- [x] GitHub Actions workflow
- [x] go fmt check
- [x] go vet static analysis
- [x] go build verification
- [x] go test with race detection
- [x] govulncheck CVE scanning
- [x] npm audit for frontend

### SDK

- [x] Token validation SDK (backend/pkg/sdk)
- [x] JWKS caching with configurable TTL
- [x] Wildcard scope matching
- [x] Gin middleware
- [x] Standard http middleware
- [x] Unit tests

### Phase 1 Complete

- [x] API Resources page in admin UI
- [x] Client secret rotation endpoint
- [x] Client scope restriction enforcement
- [x] All Phase 1 items completed

### Phase 2 Complete

- [x] Prometheus metrics (internal/metrics package)
- [x] Token issuance, validation, auth failure counters
- [x] Rate limit violation tracking
- [x] Active tokens gauge
- [x] Detailed health endpoints (/health/live, /health/ready, /health/detailed)
- [x] M2M integration guide (docs/m2m-integration.md)
- [x] OpenAPI specification (docs/openapi.yaml)
- [x] Alerting integration (internal/alerting package)

### Multi-tenancy

- [x] Tenant model and database schema
- [x] Tenant CRUD API endpoints
- [x] tenant_id claim in JWT tokens
- [x] Tenant management admin UI
- [x] Application-tenant association
- [x] Tenant status management (active/suspended/revoked)

### DPoP (RFC 9449)

- [x] DPoP proof validation
- [x] JWK thumbprint calculation (RFC 7638)
- [x] Token binding via cnf/jkt claim
- [x] Replay attack prevention (JTI tracking)
- [x] Access token hash (ath) validation
- [x] RSA and EC key support
- [x] Discovery endpoint dpop_signing_alg_values_supported
