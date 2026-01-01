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

---

## Part 1: OryxID Admin Setup

This section is for OryxID administrators. Configure via OryxID frontend.

### 1.1 Create Scopes

Navigate to **Scopes** in OryxID frontend and create:

| Scope Name | Description |
|------------|-------------|
| `trustsky:admin` | Full admin access (expands to all scopes) |
| `trustsky:flight:read` | Read flight data |
| `trustsky:flight:write` | Write flight data (includes read) |
| `trustsky:nfz:read` | Read no-fly zones |
| `trustsky:nfz:write` | Write no-fly zones (includes read) |
| `trustsky:operator:read` | Read operator data |
| `trustsky:operator:write` | Write operator data (includes read) |
| `trustsky:telemetry:write` | Write telemetry data |
| `trustsky:sky:read` | Read sky data |

### 1.2 Create Tenant (if multi-tenancy needed)

Navigate to **Tenants** and create:

| Field | Value |
|-------|-------|
| Name | Organization name (e.g., "Acme Drone Operations") |
| Type | `operator`, `authority`, or `emergency_service` |
| Email | Contact email |
| Status | `active` |

### 1.3 Create Application for TrustSky

Navigate to **Applications** and create:

| Field | Value |
|-------|-------|
| Name | `TrustSky Backend` |
| Client Type | `confidential` |
| Grant Types | `client_credentials` |
| Token Endpoint Auth | `client_secret_basic` |
| Scopes | Select all trustsky:* scopes needed |
| Tenant | Select tenant (if multi-tenancy) |

After creation, copy:
- **Client ID** → provide to TrustSky as `AUTH_CLIENT_ID`
- **Client Secret** → provide to TrustSky as `AUTH_CLIENT_SECRET`

---

## Part 2: TrustSky Client Configuration

This section is for TrustSky deployment. Use credentials provided by OryxID admin.

### 2.1 Environment Variables

```bash
AUTH_ENABLED=true
AUTH_ISSUER=http://localhost:9000
AUTH_JWKS_URL=${AUTH_ISSUER}/.well-known/jwks.json
AUTH_AUDIENCE=trustsky
AUTH_CLOCK_SKEW=30s
AUTH_CLIENT_ID=<provided-by-oryxid-admin>
AUTH_CLIENT_SECRET=<provided-by-oryxid-admin>
```

### 2.2 Obtain Access Token

Use `AUTH_CLIENT_ID` and `AUTH_CLIENT_SECRET` to get a bearer token:

```bash
curl -X POST $AUTH_ISSUER/oauth/token \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=trustsky:flight:write"
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

Use `access_token` as bearer token for API requests:
```bash
curl -X GET $API_URL/flights \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

### 2.3 Token Claims

Decoded JWT contains:

```json
{
  "iss": "http://localhost:9000",
  "sub": "client-id",
  "aud": "trustsky",
  "exp": 1704067200,
  "iat": 1704063600,
  "scope": "trustsky:flight:write trustsky:flight:read",
  "client_id": "client-id",
  "tenant_id": "uuid"
}
```

---

## Endpoints

| Purpose | URL |
|---------|-----|
| Discovery | `$AUTH_ISSUER/.well-known/openid-configuration` |
| JWKS | `$AUTH_ISSUER/.well-known/jwks.json` |
| Token | `$AUTH_ISSUER/oauth/token` |
| Introspection | `$AUTH_ISSUER/oauth/introspect` |
| Revocation | `$AUTH_ISSUER/oauth/revoke` |

---

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

### Introspection

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
  "client_id": "client-id",
  "tenant_id": "uuid",
  "exp": 1704067200
}
```

---

## Scope Hierarchy

OryxID auto-expands scopes:

| Requested | Token Contains |
|-----------|----------------|
| `trustsky:admin` | All trustsky:* scopes |
| `trustsky:flight:write` | `flight:write` + `flight:read` |
| `trustsky:nfz:write` | `nfz:write` + `nfz:read` |
| `trustsky:operator:write` | `operator:write` + `operator:read` |
| `trustsky:flight:read` | `flight:read` only |

---

## Tenant Status

| Status | Token Issuance |
|--------|----------------|
| `active` | Allowed |
| `suspended` | Blocked |
| `revoked` | Blocked |

---

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

---

## Errors

| Error | Cause |
|-------|-------|
| `invalid_client` | Wrong client_id or secret |
| `tenant is suspended` | Tenant suspended |
| `tenant is revoked` | Tenant revoked |
| `invalid_scope` | Scope not allowed |
| `invalid_dpop_proof` | DPoP validation failed |

---

## Checklist

### OryxID Admin
- [ ] Scopes created (all trustsky:* scopes)
- [ ] Tenant created (if needed)
- [ ] Application created with correct settings
- [ ] Client ID and Secret provided to TrustSky

### TrustSky
- [ ] Environment variables configured
- [ ] Token generation working
- [ ] Token validation implemented
- [ ] Scope checking implemented
