# TrustSky USSP Integration Guide

This document explains how to integrate OryxID with TrustSky UTM Service Supplier Platform.

## Overview

OryxID provides OAuth 2.1 / OpenID Connect compliant identity services for TrustSky USSP integration. Key features:

- Multi-tenancy with `tenant_id` claim in JWT tokens
- DPoP (RFC 9449) for sender-constrained tokens
- TrustSky-specific scope hierarchy
- Token introspection (RFC 7662)
- JWKS endpoint for token validation

## Quick Start

### 1. Create a Tenant

Each operator/organization needs a tenant:

```bash
curl -X POST https://oryxid.example.com/api/tenants \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Drone Operations",
    "type": "operator",
    "email": "admin@acme.com"
  }'
```

Response includes `id` which becomes the `tenant_id` in tokens.

### 2. Create an Application for the Tenant

```bash
curl -X POST https://oryxid.example.com/api/applications \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Acme Flight Control",
    "client_type": "confidential",
    "grant_types": ["client_credentials"],
    "redirect_uris": ["https://acme.com/callback"],
    "scope_ids": ["<scope_id_for_trustsky_flight_write>"],
    "tenant_id": "<tenant_id_from_step_1>"
  }'
```

Save the `client_id` and `client_secret` from the response.

### 3. Obtain Access Token

```bash
curl -X POST https://oryxid.example.com/oauth/token \
  -u "<client_id>:<client_secret>" \
  -d "grant_type=client_credentials" \
  -d "scope=trustsky:flight:write"
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

Note: `trustsky:flight:write` automatically includes `trustsky:flight:read` via scope hierarchy.

## JWT Token Structure

Decoded access token payload:

```json
{
  "iss": "https://oryxid.example.com",
  "sub": "client_id_here",
  "aud": "trustsky-api",
  "exp": 1704067200,
  "iat": 1704063600,
  "scope": "trustsky:flight:write trustsky:flight:read",
  "client_id": "client_id_here",
  "tenant_id": "uuid-of-tenant"
}
```

The `tenant_id` identifies which operator/organization the token belongs to.

## DPoP (Proof-of-Possession Tokens)

DPoP binds tokens to a specific client key pair, preventing token theft.

### Client Setup

1. Generate an EC or RSA key pair
2. Create DPoP proof JWT for each request

### Token Request with DPoP

```bash
# Generate DPoP proof (example using jose-cli or similar)
DPOP_PROOF=$(create_dpop_proof \
  --method POST \
  --uri https://oryxid.example.com/oauth/token \
  --key private_key.pem)

curl -X POST https://oryxid.example.com/oauth/token \
  -H "DPoP: $DPOP_PROOF" \
  -u "<client_id>:<client_secret>" \
  -d "grant_type=client_credentials"
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "DPoP",
  "expires_in": 3600
}
```

### DPoP Proof Structure

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "...",
    "y": "..."
  }
}
```

Claims:
```json
{
  "jti": "unique-id",
  "htm": "POST",
  "htu": "https://oryxid.example.com/oauth/token",
  "iat": 1704063600
}
```

### DPoP-Bound Token

The token includes a confirmation claim:
```json
{
  "cnf": {
    "jkt": "sha256-thumbprint-of-jwk"
  }
}
```

### Using DPoP Token at Resource Server

```bash
# For resource requests, include ath (access token hash)
DPOP_PROOF=$(create_dpop_proof \
  --method GET \
  --uri https://trustsky.example.com/api/flights \
  --key private_key.pem \
  --access-token $ACCESS_TOKEN)

curl https://trustsky.example.com/api/flights \
  -H "Authorization: DPoP $ACCESS_TOKEN" \
  -H "DPoP: $DPOP_PROOF"
```

## Scope Hierarchy

TrustSky scopes follow a hierarchical model:

| Scope | Includes |
|-------|----------|
| `trustsky:admin` | All scopes below |
| `trustsky:flight:write` | `trustsky:flight:read` |
| `trustsky:nfz:write` | `trustsky:nfz:read` |
| `trustsky:operator:write` | `trustsky:operator:read` |
| `trustsky:telemetry:write` | (no read equivalent) |
| `trustsky:sky:read` | (read-only) |

When a token has `trustsky:flight:write`, APIs requiring `trustsky:flight:read` will also accept it.

## Token Introspection

Resource servers validate tokens using introspection:

```bash
curl -X POST https://oryxid.example.com/oauth/introspect \
  -u "<resource_server_client_id>:<client_secret>" \
  -d "token=<access_token>"
```

Response:
```json
{
  "active": true,
  "scope": "trustsky:flight:write trustsky:flight:read",
  "client_id": "client_id_here",
  "tenant_id": "uuid-of-tenant",
  "exp": 1704067200,
  "iat": 1704063600,
  "sub": "client_id_here"
}
```

## JWKS Endpoint

For JWT validation without introspection:

```
GET https://oryxid.example.com/.well-known/jwks.json
```

Response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-id",
      "alg": "RS256",
      "n": "base64url-encoded-modulus",
      "e": "AQAB"
    }
  ]
}
```

## Discovery Endpoint

```
GET https://oryxid.example.com/.well-known/openid-configuration
```

Key fields:
- `token_endpoint`: Token issuance
- `introspection_endpoint`: Token validation
- `jwks_uri`: Public keys
- `dpop_signing_alg_values_supported`: DPoP algorithms

## Frontend DPoP Implementation (JavaScript)

```javascript
// Generate key pair (once, store securely)
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,
  ['sign', 'verify']
);

// Export public key as JWK
const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

// Create DPoP proof
async function createDPoPProof(method, uri, accessToken = null) {
  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: {
      kty: publicJwk.kty,
      crv: publicJwk.crv,
      x: publicJwk.x,
      y: publicJwk.y
    }
  };

  const payload = {
    jti: crypto.randomUUID(),
    htm: method,
    htu: uri,
    iat: Math.floor(Date.now() / 1000)
  };

  // Add access token hash for resource requests
  if (accessToken) {
    const encoder = new TextEncoder();
    const data = encoder.encode(accessToken);
    const hash = await crypto.subtle.digest('SHA-256', data);
    payload.ath = btoa(String.fromCharCode(...new Uint8Array(hash)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  // Sign the JWT (use jose library or similar)
  // return signedJwt;
}

// Token request
const dpopProof = await createDPoPProof('POST', 'https://oryxid.example.com/oauth/token');

const response = await fetch('https://oryxid.example.com/oauth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'DPoP': dpopProof
  },
  body: new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: 'your-client-id',
    client_secret: 'your-client-secret'
  })
});
```

## Error Handling

### Invalid DPoP Proof

```json
{
  "error": "invalid_dpop_proof",
  "error_description": "dpop htm mismatch: expected POST, got GET"
}
```

Common issues:
- Wrong HTTP method in proof
- Wrong URI in proof
- Proof expired (older than 5 minutes)
- JTI reuse (replay attack prevention)

### Token Validation Errors

```json
{
  "active": false
}
```

Or for DPoP-bound tokens presented without matching proof:
```json
{
  "error": "invalid_token",
  "error_description": "dpop proof thumbprint does not match token binding"
}
```

## Configuration Reference

### Tenant Types

| Type | Description |
|------|-------------|
| `operator` | Commercial/recreational drone operators |
| `authority` | Regulatory bodies, air traffic control |
| `emergency_service` | Police, fire, medical services |

### Token Lifetimes

| Token Type | Default Lifetime |
|------------|-----------------|
| Access Token | 1 hour |
| Refresh Token | 30 days |
| ID Token | 1 hour |

TrustSky recommends refresh token lifetime <= 7 days for production.

## Checklist

Before going to production:

- [ ] Create tenant for each operator/organization
- [ ] Configure appropriate scopes for each application
- [ ] Test token introspection from resource servers
- [ ] Implement DPoP if sender-constrained tokens required
- [ ] Configure refresh token rotation
- [ ] Set up audit logging
- [ ] Review token lifetimes for TrustSky compliance
