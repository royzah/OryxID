# OryxID Roadmap

## Overview

```mermaid
flowchart LR
    P1[Phase 1: Security] --> P2[Phase 2: Self-Service]
    P2 --> P3[Phase 3: Operations]
    P3 --> P4[Phase 4: Enterprise]
    P4 --> P5[Phase 5: Advanced]
```

## Current Status

```mermaid
pie title Production Readiness
    "Completed" : 55
    "Remaining" : 45
```

---

## Phase 1: Security Hardening

Critical security features required before production deployment.

```mermaid
flowchart TD
    A[Account Lockout] --> B[Password Policy]
    B --> C[Session Security]
    C --> D[Security Logging]
```

### Account Protection

- [ ] Account lockout after failed login attempts
- [ ] Configurable lockout threshold and duration
- [ ] Exponential backoff on repeated failures
- [ ] Admin unlock capability

### Password Policy

- [ ] Minimum length configuration (default: 12)
- [ ] Complexity requirements (uppercase, lowercase, number, special)
- [ ] Password history prevention
- [ ] Password expiration policy
- [ ] Force password change on first login

### Session Security

- [ ] Maximum concurrent sessions per user
- [ ] Session timeout on inactivity
- [ ] Revoke all sessions on password change
- [ ] Token binding to IP/fingerprint (optional)

### Security Events

- [ ] Failed login attempt logging with alerts
- [ ] Suspicious activity detection
- [ ] Security event webhook notifications

---

## Phase 2: User Self-Service

Enable users to manage their own accounts.

```mermaid
flowchart TD
    A[Email Integration] --> B[Password Reset]
    B --> C[Email Verification]
    C --> D[Self-Registration]
```

### Email Integration

- [ ] Email provider abstraction (SMTP, SendGrid, AWS SES)
- [ ] Email templates (HTML + plaintext)
- [ ] Email queue with retry logic

### Password Reset

- [ ] Forgot password endpoint
- [ ] Secure reset token generation
- [ ] Reset token expiration
- [ ] Reset confirmation email

### Email Verification

- [ ] Verification email on registration
- [ ] Resend verification endpoint
- [ ] Enforce verified email for login (configurable)

### Self-Registration

- [ ] Public registration endpoint (configurable)
- [ ] CAPTCHA integration
- [ ] Registration approval workflow (optional)

---

## Phase 3: Operations

Production observability and operational tooling.

```mermaid
flowchart TD
    A[Metrics] --> B[Dashboards]
    B --> C[Alerting]
    C --> D[Backup/Restore]
    D --> E[Documentation]
```

### Prometheus Metrics

- [ ] HTTP request latency histograms
- [ ] OAuth flow counters (by grant type)
- [ ] Token issuance rates
- [ ] Failed authentication counter
- [ ] Active sessions gauge
- [ ] Rate limit violation counter
- [ ] Database connection pool stats
- [ ] Redis connection pool stats

### Dashboards

- [ ] Grafana dashboard templates
- [ ] Authentication overview
- [ ] OAuth flow analytics
- [ ] Error rate monitoring
- [ ] Resource utilization

### Alerting

- [ ] High error rate alerts
- [ ] Failed login spike detection
- [ ] Database connection exhaustion
- [ ] Certificate expiration warning

### Backup and Recovery

- [ ] Automated database backup script
- [ ] Point-in-time recovery documentation
- [ ] Backup verification procedure
- [ ] Disaster recovery runbook

### Documentation

- [ ] OpenAPI/Swagger specification
- [ ] Deployment runbook
- [ ] Upgrade procedures
- [ ] Rollback procedures
- [ ] Troubleshooting guide
- [ ] Security hardening guide

---

## Phase 4: Enterprise Features

Features required for enterprise adoption.

```mermaid
flowchart TD
    A[LDAP/AD] --> B[Social Login]
    B --> C[User Groups]
    C --> D[Multi-Tenancy]
```

### Directory Integration

- [ ] LDAP connector
- [ ] Active Directory support
- [ ] User sync scheduling
- [ ] Group mapping to roles

### Social Login

- [ ] OAuth provider abstraction
- [ ] Google connector
- [ ] GitHub connector
- [ ] Microsoft connector
- [ ] Custom provider support

### User Groups

- [ ] Group management API
- [ ] Group-based role assignment
- [ ] Nested groups support

### Multi-Tenancy

- [ ] Tenant/organization model
- [ ] Tenant isolation
- [ ] Per-tenant configuration
- [ ] Tenant admin delegation

---

## Phase 5: Advanced Features

Extended functionality for specialized use cases.

```mermaid
flowchart TD
    A[DPoP] --> B[Step-Up Auth]
    B --> C[WebAuthn]
    C --> D[Analytics]
```

### Token Security

- [ ] DPoP (Demonstrating Proof of Possession)
- [ ] Sender-constrained tokens

### Adaptive Authentication

- [ ] Step-up authentication
- [ ] Risk-based authentication
- [ ] Geolocation policies

### Passwordless

- [ ] WebAuthn/FIDO2 support
- [ ] Passkey registration
- [ ] Passkey authentication

### Analytics

- [ ] Login analytics dashboard
- [ ] User activity reports
- [ ] OAuth client usage statistics
- [ ] Export capabilities

---

## Completed

### OAuth 2.1 Core

- [x] Authorization Code with PKCE (S256)
- [x] Client Credentials
- [x] Refresh Token with rotation
- [x] Token Introspection (RFC 7662)
- [x] Token Revocation (RFC 7009)
- [x] OIDC Discovery
- [x] JWKS endpoint

### Advanced OAuth

- [x] Device Authorization (RFC 8628)
- [x] Token Exchange (RFC 8693)
- [x] Pushed Authorization Requests (RFC 9126)
- [x] Rich Authorization Requests (RFC 9396)
- [x] CIBA (OpenID Connect Backchannel Authentication)

### Security

- [x] MFA/2FA with TOTP
- [x] Backup codes
- [x] CSRF protection
- [x] Rate limiting
- [x] Security headers
- [x] TLS 1.2+ support
- [x] Let's Encrypt integration

### Infrastructure

- [x] Docker support
- [x] Docker Compose (dev + prod)
- [x] Kubernetes Helm chart
- [x] PostgreSQL support
- [x] Redis integration
- [x] Nginx reverse proxy

### Admin

- [x] Admin dashboard
- [x] User management
- [x] Application management
- [x] Scope management
- [x] Audience management
- [x] Audit logging
