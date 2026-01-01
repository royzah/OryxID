# TrustSky USSP Integration Guide

## OryxID Capabilities

| Requirement | Feature | Status |
|-------------|---------|--------|
| JWT Authentication | RS256 signed JWTs | Ready |
| JWKS Endpoint | `/.well-known/jwks.json` | Ready |
| Multi-tenancy | `tenant_id` claim in tokens | Ready |
| Scope Hierarchy | Auto-expansion (write includes read) | Ready |
| Token Introspection | RFC 7662 `/oauth/introspect` | Ready |
| DPoP | RFC 9449 sender-constrained tokens | Ready |
| Client Credentials | Machine-to-machine auth | Ready |
| Token Revocation | RFC 7009 `/oauth/revoke` | Ready |

## TrustSky Environment Variables

```bash
AUTH_ENABLED=true
AUTH_ISSUER=http://localhost:9000
AUTH_JWKS_URL=${AUTH_ISSUER}/.well-known/jwks.json
AUTH_AUDIENCE=trustsky
AUTH_CLOCK_SKEW=30s
AUTH_CLIENT_ID=<from-oryxid>
AUTH_CLIENT_SECRET=<from-oryxid>
```

## Endpoints

| Purpose | URL |
|---------|-----|
| Discovery | `$AUTH_ISSUER/.well-known/openid-configuration` |
| JWKS | `$AUTH_ISSUER/.well-known/jwks.json` |
| Token | `$AUTH_ISSUER/oauth/token` |
| Introspection | `$AUTH_ISSUER/oauth/introspect` |
| Revocation | `$AUTH_ISSUER/oauth/revoke` |

## Setup

### 1. Create Application

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

Response contains `client_id` and `client_secret` for `AUTH_CLIENT_ID` and `AUTH_CLIENT_SECRET`.

### 2. Create Scopes

```bash
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
  -d '{"scope_ids": ["<scope_id_1>", "<scope_id_2>"]}'
```

## Token Operations

### Obtain Token

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
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "trustsky:flight:write trustsky:flight:read"
}
```

### Token Claims

```json
{
  "iss": "$AUTH_ISSUER",
  "sub": "$AUTH_CLIENT_ID",
  "aud": "$AUTH_AUDIENCE",
  "exp": 1704067200,
  "iat": 1704063600,
  "scope": "trustsky:flight:write trustsky:flight:read",
  "client_id": "$AUTH_CLIENT_ID",
  "tenant_id": "uuid"
}
```

### Introspect Token

```bash
curl -X POST $AUTH_ISSUER/oauth/introspect \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -d "token=<access_token>"
```

### Revoke Token

```bash
curl -X POST $AUTH_ISSUER/oauth/revoke \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -d "token=<access_token>"
```

## Token Validation

### JWKS Validation (Recommended)

Go:
```go
import "github.com/golang-jwt/jwt/v5"

// Fetch JWKS from $AUTH_JWKS_URL
// Validate signature with public key
// Check iss, aud, exp, scope claims
```

Node.js:
```javascript
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

### Introspection Validation

```bash
curl -X POST $AUTH_ISSUER/oauth/introspect \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -d "token=<access_token>"
```

Response:
```json
{
  "active": true,
  "scope": "trustsky:flight:write trustsky:flight:read",
  "client_id": "ts_abc123",
  "tenant_id": "uuid",
  "exp": 1704067200
}
```

## Scope Hierarchy

OryxID auto-expands scopes:

| Requested | Token Contains |
|-----------|----------------|
| `trustsky:admin` | All trustsky:* scopes |
| `trustsky:flight:write` | `flight:write` + `flight:read` |
| `trustsky:nfz:write` | `nfz:write` + `nfz:read` |
| `trustsky:operator:write` | `operator:write` + `operator:read` |
| `trustsky:flight:read` | `flight:read` only |

### Scope Check Example

```go
func hasScope(tokenScopes, required string) bool {
    for _, s := range strings.Split(tokenScopes, " ") {
        if s == required {
            return true
        }
    }
    return false
}
```

## Multi-Tenancy

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
| `operator` | Drone operators |
| `authority` | Regulatory bodies |
| `emergency_service` | Emergency services |

### Tenant Status

| Status | Token Issuance |
|--------|----------------|
| `active` | Allowed |
| `suspended` | Blocked |
| `revoked` | Blocked |

## DPoP (Optional)

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

### DPoP Proof

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

### DPoP Token Contains

```json
{
  "cnf": { "jkt": "sha256-thumbprint" }
}
```

## Errors

| Error | Cause |
|-------|-------|
| `invalid_client` | Wrong client_id or secret |
| `tenant is suspended` | Tenant suspended |
| `tenant is revoked` | Tenant revoked |
| `invalid_scope` | Scope not allowed |
| `invalid_dpop_proof` | DPoP validation failed |

## Checklist

- [ ] OryxID deployed at `$AUTH_ISSUER`
- [ ] Application created with client credentials
- [ ] Scopes created and assigned
- [ ] Tenants created for operators
- [ ] Environment variables configured
- [ ] Token validation implemented
- [ ] Scope checking implemented
- [ ] Tenant isolation verified
