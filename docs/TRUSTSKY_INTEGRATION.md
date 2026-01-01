# TrustSky USSP Integration Guide

This document explains how to integrate TrustSky with OryxID as the authentication provider.

## What OryxID Provides

| TrustSky Requirement | OryxID Feature | Status |
|---------------------|----------------|--------|
| JWT Authentication | RS256 signed JWTs with configurable issuer | Ready |
| JWKS Endpoint | `/.well-known/jwks.json` for public key distribution | Ready |
| Multi-tenancy | `tenant_id` claim in all tokens | Ready |
| Scope Hierarchy | `trustsky:admin` -> all, `write` -> `read` auto-expansion | Ready |
| Token Introspection | RFC 7662 compliant `/oauth/introspect` endpoint | Ready |
| DPoP (Optional) | RFC 9449 sender-constrained tokens | Ready |
| Client Credentials | Machine-to-machine authentication | Ready |
| Token Revocation | RFC 7009 compliant `/oauth/revoke` endpoint | Ready |

## TrustSky Environment Configuration

Add these environment variables to your TrustSky deployment:

```bash
# =============================================================================
# AUTHENTICATION (OryxID)
# =============================================================================
AUTH_ENABLED=true
AUTH_ISSUER=http://localhost:9000
AUTH_JWKS_URL=http://localhost:9000/.well-known/jwks.json
AUTH_AUDIENCE=trustsky

# Clock skew tolerance for JWT validation
AUTH_CLOCK_SKEW=30s

# Client credentials for obtaining access tokens
AUTH_CLIENT_ID=your-trustsky-client-id
AUTH_CLIENT_SECRET=your-trustsky-client-secret
```

## OryxID Endpoints

| Purpose | Endpoint |
|---------|----------|
| OpenID Discovery | `$AUTH_ISSUER/.well-known/openid-configuration` |
| JWKS (Public Keys) | `$AUTH_ISSUER/.well-known/jwks.json` |
| Token Endpoint | `$AUTH_ISSUER/oauth/token` |
| Introspection | `$AUTH_ISSUER/oauth/introspect` |
| Revocation | `$AUTH_ISSUER/oauth/revoke` |

## Setup Steps

### 1. Create TrustSky Application in OryxID

Create an application for TrustSky backend services:

```bash
curl -X POST $AUTH_ISSUER/api/applications \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TrustSky Backend",
    "client_type": "confidential",
    "grant_types": ["client_credentials"],
    "token_endpoint_auth_method": "client_secret_basic"
  }'
```

Response:
```json
{
  "id": "uuid",
  "client_id": "ts_abc123",
  "client_secret": "secret_xyz789",
  "name": "TrustSky Backend"
}
```

Use these values for `AUTH_CLIENT_ID` and `AUTH_CLIENT_SECRET`.

### 2. Create Scopes

Create the TrustSky scopes in OryxID:

```bash
# Create scopes
for scope in trustsky:admin trustsky:flight:read trustsky:flight:write \
             trustsky:nfz:read trustsky:nfz:write trustsky:telemetry:write \
             trustsky:sky:read trustsky:operator:read trustsky:operator:write; do
  curl -X POST $AUTH_ISSUER/api/scopes \
    -H "Authorization: Bearer <admin_token>" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"$scope\"}"
done
```

### 3. Assign Scopes to Application

```bash
curl -X PUT $AUTH_ISSUER/api/applications/<app_id>/scopes \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "scope_ids": ["<scope_id_1>", "<scope_id_2>", "..."]
  }'
```

## Obtaining Access Tokens

### Client Credentials Grant

TrustSky backend services obtain tokens using client credentials:

```bash
curl -X POST $AUTH_ISSUER/oauth/token \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=trustsky:flight:write" \
  -d "audience=$AUTH_AUDIENCE"
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "trustsky:flight:write trustsky:flight:read"
}
```

Note: Scope expansion is automatic. Requesting `trustsky:flight:write` returns both `write` and `read`.

### Token Structure

Decoded JWT payload:

```json
{
  "iss": "$AUTH_ISSUER",
  "sub": "$AUTH_CLIENT_ID",
  "aud": "$AUTH_AUDIENCE",
  "exp": 1704067200,
  "iat": 1704063600,
  "scope": "trustsky:flight:write trustsky:flight:read",
  "client_id": "$AUTH_CLIENT_ID",
  "tenant_id": "uuid-of-tenant"
}
```

## Token Validation in TrustSky

### Option 1: JWKS Validation (Recommended)

Validate JWTs locally using the JWKS endpoint:

```go
// Go example
import "github.com/golang-jwt/jwt/v5"

// Fetch JWKS from $AUTH_JWKS_URL
// Validate token signature using public key
// Check claims: iss, aud, exp, scope
```

```javascript
// Node.js example using jose
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(new URL(process.env.AUTH_JWKS_URL));

async function validateToken(token) {
  const { payload } = await jwtVerify(token, JWKS, {
    issuer: process.env.AUTH_ISSUER,
    audience: process.env.AUTH_AUDIENCE,
  });
  return payload;
}
```

### Option 2: Token Introspection

For real-time token status (checks revocation):

```bash
curl -X POST $AUTH_ISSUER/oauth/introspect \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=<access_token>"
```

Response:
```json
{
  "active": true,
  "scope": "trustsky:flight:write trustsky:flight:read",
  "client_id": "ts_abc123",
  "tenant_id": "uuid-of-tenant",
  "exp": 1704067200,
  "iat": 1704063600
}
```

## Scope Hierarchy

OryxID automatically expands scopes based on hierarchy:

```
trustsky:admin
    |
    +-- trustsky:flight:write --> trustsky:flight:read
    +-- trustsky:nfz:write --> trustsky:nfz:read
    +-- trustsky:operator:write --> trustsky:operator:read
    +-- trustsky:telemetry:write
    +-- trustsky:sky:read
```

| Requested Scope | Token Contains |
|-----------------|----------------|
| `trustsky:admin` | All trustsky:* scopes |
| `trustsky:flight:write` | `trustsky:flight:write` + `trustsky:flight:read` |
| `trustsky:nfz:write` | `trustsky:nfz:write` + `trustsky:nfz:read` |
| `trustsky:flight:read` | `trustsky:flight:read` only |

### Checking Scopes in Code

```go
// Go example
func hasScope(tokenScopes, requiredScope string) bool {
    scopes := strings.Split(tokenScopes, " ")
    for _, s := range scopes {
        if s == requiredScope {
            return true
        }
    }
    return false
}

// Usage: check if token has flight:read access
if hasScope(claims.Scope, "trustsky:flight:read") {
    // Allow access
}
```

## Multi-Tenancy

Each operator/organization has a tenant in OryxID. The `tenant_id` claim identifies which tenant the token belongs to.

### Create Tenant

```bash
curl -X POST $AUTH_ISSUER/api/tenants \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Drone Operations",
    "type": "operator",
    "email": "admin@acme.com"
  }'
```

### Tenant Types

| Type | Description |
|------|-------------|
| `operator` | Commercial/recreational drone operators |
| `authority` | Regulatory bodies, air traffic control |
| `emergency_service` | Police, fire, medical services |

### Tenant Status

| Status | Token Issuance |
|--------|----------------|
| `active` | Allowed |
| `suspended` | Blocked (returns error) |
| `revoked` | Blocked (returns error) |

TrustSky can rely on OryxID blocking tokens for suspended/revoked tenants.

## DPoP (Optional)

For sender-constrained tokens, use DPoP (RFC 9449).

### Token Request with DPoP

```bash
curl -X POST $AUTH_ISSUER/oauth/token \
  -H "DPoP: <dpop_proof_jwt>" \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -d "grant_type=client_credentials"
```

Response:
```json
{
  "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 3600
}
```

### DPoP Proof Structure

Header:
```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
```

Payload:
```json
{
  "jti": "unique-id",
  "htm": "POST",
  "htu": "$AUTH_ISSUER/oauth/token",
  "iat": 1704063600
}
```

### DPoP-Bound Token

The access token contains a confirmation claim:
```json
{
  "cnf": {
    "jkt": "sha256-thumbprint-of-client-jwk"
  }
}
```

### Using DPoP Token

```bash
# Include ath (access token hash) for resource requests
curl -X GET $TRUSTSKY_API/flights \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: <dpop_proof_with_ath>"
```

## Error Handling

### Token Request Errors

| Error | Description |
|-------|-------------|
| `invalid_client` | Wrong client_id or client_secret |
| `tenant is suspended` | Tenant has been suspended |
| `tenant is revoked` | Tenant has been revoked |
| `invalid_scope` | Requested scope not allowed for client |
| `invalid_dpop_proof` | DPoP proof validation failed |

### Introspection Response

Inactive token:
```json
{
  "active": false
}
```

## Quick Reference

### Environment Variables Summary

```bash
# Required
AUTH_ENABLED=true
AUTH_ISSUER=http://localhost:9000
AUTH_JWKS_URL=${AUTH_ISSUER}/.well-known/jwks.json
AUTH_AUDIENCE=trustsky
AUTH_CLIENT_ID=<from-oryxid-application>
AUTH_CLIENT_SECRET=<from-oryxid-application>

# Optional
AUTH_CLOCK_SKEW=30s
AUTH_INTROSPECT_URL=${AUTH_ISSUER}/oauth/introspect
AUTH_TOKEN_URL=${AUTH_ISSUER}/oauth/token
```

### Common Operations

```bash
# Get access token
curl -X POST $AUTH_ISSUER/oauth/token \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=trustsky:flight:write"

# Validate token
curl -X POST $AUTH_ISSUER/oauth/introspect \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -d "token=$ACCESS_TOKEN"

# Revoke token
curl -X POST $AUTH_ISSUER/oauth/revoke \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -d "token=$ACCESS_TOKEN"

# Get JWKS
curl $AUTH_ISSUER/.well-known/jwks.json

# Get OpenID configuration
curl $AUTH_ISSUER/.well-known/openid-configuration
```

## Checklist

Before production deployment:

- [ ] OryxID deployed and accessible at `$AUTH_ISSUER`
- [ ] TrustSky application created with `AUTH_CLIENT_ID` and `AUTH_CLIENT_SECRET`
- [ ] Required scopes created and assigned to application
- [ ] Tenants created for each operator/organization
- [ ] TrustSky configured with environment variables above
- [ ] Token validation working (JWKS or introspection)
- [ ] Scope checking implemented in TrustSky APIs
- [ ] Tenant isolation verified (check `tenant_id` in requests)
