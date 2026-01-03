# TrustSky USSP Integration with OryxID

OryxID is an OAuth 2.1 / OpenID Connect authorization server that provides authentication and authorization for TrustSky USSP.

## What OryxID Provides

| Feature | Description | Specification |
| --------- | ------------- | --------------- |
| JWT Access Tokens | RS256 signed tokens with claims | RFC 9068 |
| JWKS Endpoint | Public keys for token verification | RFC 7517 |
| Token Introspection | Validate tokens server-side | RFC 7662 |
| Token Revocation | Revoke access/refresh tokens | RFC 7009 |
| Multi-tenancy | `tenant_id` claim for organization isolation | Custom |
| Scope Hierarchy | `write` automatically includes `read` | Custom |
| DPoP | Sender-constrained tokens (optional) | RFC 9449 |
| Client Credentials | Machine-to-machine authentication | RFC 6749 |

---

## Quick Start for TrustSky Developers

### 1. Get Credentials from OryxID Admin

Required credentials from OryxID administrator:

```bash
AUTH_ISSUER=https://auth.example.com      # OryxID server URL
AUTH_CLIENT_ID=<client-id>                # UUID format
AUTH_CLIENT_SECRET=<client-secret>        # 64-character secret
```

### 2. Test Token Generation

```bash
# Get an access token
curl -X POST ${AUTH_ISSUER}/oauth/token \
  -u "${AUTH_CLIENT_ID}:${AUTH_CLIENT_SECRET}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=trustsky:flight:write"
```

Response:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRlZmF1bHQta2V5LWlkIn0...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "trustsky:flight:write trustsky:flight:read"
}
```

### 3. Use Token in API Requests

```bash
curl -X GET https://api.trustsky.example.com/v1/flights \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

---

## OryxID Endpoints

All endpoints are relative to `AUTH_ISSUER`:

| Endpoint | Method | Description |
| ---------- | -------- | ------------- |
| `/.well-known/openid-configuration` | GET | OpenID Connect discovery document |
| `/.well-known/jwks.json` | GET | JSON Web Key Set (public keys) |
| `/oauth/token` | POST | Token endpoint (get access tokens) |
| `/oauth/introspect` | POST | Token introspection (validate tokens) |
| `/oauth/revoke` | POST | Token revocation |

### Discovery Document

```bash
curl ${AUTH_ISSUER}/.well-known/openid-configuration
```

Response:

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth/authorize",
  "token_endpoint": "https://auth.example.com/oauth/token",
  "introspection_endpoint": "https://auth.example.com/oauth/introspect",
  "revocation_endpoint": "https://auth.example.com/oauth/revoke",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "response_types_supported": ["code"],
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "dpop_signing_alg_values_supported": ["ES256", "RS256"]
}
```

---

## JWT Access Token Structure

### Token Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "default-key-id"
}
```

### Token Payload

```json
{
  "iss": "https://auth.example.com",
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "aud": "trustsky",
  "exp": 1704067200,
  "iat": 1704063600,
  "jti": "unique-token-id",
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "scope": "trustsky:flight:write trustsky:flight:read",
  "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

### Claims Reference

| Claim | Type | Description |
| ------- | ------ | ------------- |
| `iss` | string | Issuer URL (AUTH_ISSUER) |
| `sub` | string | Subject (client_id for client_credentials) |
| `aud` | string | Audience (e.g., "trustsky") |
| `exp` | number | Expiration time (Unix timestamp) |
| `iat` | number | Issued at time (Unix timestamp) |
| `jti` | string | Unique token identifier |
| `client_id` | string | OAuth client ID |
| `scope` | string | Space-separated list of granted scopes |
| `tenant_id` | string | Tenant UUID (for multi-tenancy) |

---

## Token Validation

### Option 1: JWKS Validation (Recommended)

Validate tokens locally using the public key from JWKS endpoint.

**Go Example:**

```go
package auth

import (
    "context"
    "fmt"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/lestrrat-go/jwx/v2/jwk"
)

type TokenValidator struct {
    issuer   string
    audience string
    jwks     jwk.Set
}

func NewTokenValidator(issuer, audience string) (*TokenValidator, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    jwksURL := issuer + "/.well-known/jwks.json"
    set, err := jwk.Fetch(ctx, jwksURL)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
    }

    return &TokenValidator{
        issuer:   issuer,
        audience: audience,
        jwks:     set,
    }, nil
}

type Claims struct {
    jwt.RegisteredClaims
    ClientID string `json:"client_id"`
    Scope    string `json:"scope"`
    TenantID string `json:"tenant_id"`
}

func (v *TokenValidator) Validate(tokenString string) (*Claims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
        kid, ok := token.Header["kid"].(string)
        if !ok {
            return nil, fmt.Errorf("missing kid in token header")
        }

        key, found := v.jwks.LookupKeyID(kid)
        if !found {
            return nil, fmt.Errorf("key %s not found in JWKS", kid)
        }

        var pubKey interface{}
        if err := key.Raw(&pubKey); err != nil {
            return nil, fmt.Errorf("failed to get public key: %w", err)
        }
        return pubKey, nil
    })
    if err != nil {
        return nil, fmt.Errorf("token validation failed: %w", err)
    }

    claims, ok := token.Claims.(*Claims)
    if !ok || !token.Valid {
        return nil, fmt.Errorf("invalid token claims")
    }

    // Verify issuer
    if claims.Issuer != v.issuer {
        return nil, fmt.Errorf("invalid issuer: expected %s, got %s", v.issuer, claims.Issuer)
    }

    // Verify audience
    if !claims.VerifyAudience(v.audience, true) {
        return nil, fmt.Errorf("invalid audience")
    }

    return claims, nil
}

// HasScope checks if the token has a specific scope
func (c *Claims) HasScope(scope string) bool {
    scopes := strings.Split(c.Scope, " ")
    for _, s := range scopes {
        if s == scope {
            return true
        }
    }
    return false
}
```

**HTTP Middleware Example (Go):**

```go
package middleware

import (
    "net/http"
    "strings"
)

// AuthMiddleware validates JWT tokens and checks scopes
func AuthMiddleware(validator *TokenValidator, requiredScope string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            authHeader := r.Header.Get("Authorization")
            if !strings.HasPrefix(authHeader, "Bearer ") {
                http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
                return
            }

            token := strings.TrimPrefix(authHeader, "Bearer ")
            claims, err := validator.Validate(token)
            if err != nil {
                http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
                return
            }

            if !claims.HasScope(requiredScope) {
                http.Error(w, `{"error":"insufficient scope"}`, http.StatusForbidden)
                return
            }

            // Add claims to request context
            ctx := context.WithValue(r.Context(), "claims", claims)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

### Option 2: Token Introspection

Validate tokens by calling OryxID's introspection endpoint. Use this for real-time revocation checking.

```bash
curl -X POST ${AUTH_ISSUER}/oauth/introspect \
  -u "${AUTH_CLIENT_ID}:${AUTH_CLIENT_SECRET}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${ACCESS_TOKEN}"
```

**Go Example:**

```go
package auth

import (
    "encoding/json"
    "fmt"
    "net/http"
    "net/url"
    "strings"
)

type IntrospectionResponse struct {
    Active   bool   `json:"active"`
    ClientID string `json:"client_id"`
    Scope    string `json:"scope"`
    TenantID string `json:"tenant_id"`
    Exp      int64  `json:"exp"`
    Iat      int64  `json:"iat"`
}

func (v *TokenValidator) Introspect(token string) (*IntrospectionResponse, error) {
    data := url.Values{}
    data.Set("token", token)

    req, err := http.NewRequest("POST", v.issuer+"/oauth/introspect", strings.NewReader(data.Encode()))
    if err != nil {
        return nil, err
    }
    req.SetBasicAuth(v.clientID, v.clientSecret)
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var result IntrospectionResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }

    if !result.Active {
        return nil, fmt.Errorf("token is not active")
    }
    return &result, nil
}
```

Response (active token):

```json
{
  "active": true,
  "client_id": "550e8400-e29b-41d4-a716-446655440000",
  "scope": "trustsky:flight:write trustsky:flight:read",
  "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "exp": 1704067200,
  "iat": 1704063600,
  "token_type": "Bearer"
}
```

Response (revoked/expired token):

```json
{
  "active": false
}
```

---

## Scope Hierarchy

OryxID automatically expands scopes following this hierarchy:

```text
trustsky:admin
  └── trustsky:flight:write
  │     └── trustsky:flight:read
  └── trustsky:nfz:write
  │     └── trustsky:nfz:read
  └── trustsky:operator:write
  │     └── trustsky:operator:read
  └── trustsky:telemetry:write
  └── trustsky:sky:read
```

### Expansion Rules

| Request This | Token Contains |
| -------------- | ---------------- |
| `trustsky:admin` | All trustsky:* scopes |
| `trustsky:flight:write` | `trustsky:flight:write` + `trustsky:flight:read` |
| `trustsky:nfz:write` | `trustsky:nfz:write` + `trustsky:nfz:read` |
| `trustsky:operator:write` | `trustsky:operator:write` + `trustsky:operator:read` |
| `trustsky:flight:read` | `trustsky:flight:read` only |

---

## Multi-Tenancy

Each application in OryxID can be assigned to a tenant. The `tenant_id` claim in the token identifies which organization the client belongs to.

### Tenant Isolation

Use `tenant_id` to filter data:

```go
func (s *FlightService) ListFlights(ctx context.Context, claims *Claims) ([]Flight, error) {
    // Only return flights for this tenant
    return s.repo.FindByTenantID(ctx, claims.TenantID)
}
```

### Tenant Status

| Status | Token Issuance | Description |
| -------- | ---------------- | ------------- |
| `active` | Allowed | Normal operation |
| `suspended` | Blocked | Temporary suspension |
| `revoked` | Blocked | Permanent revocation |

---

## API Resources (Audiences)

API Resources allow registering protected APIs and defining which scopes each API accepts. The identifier appears in the `aud` (audience) claim of tokens.

### Create API Resource

In OryxID admin UI, navigate to **API Resources** and create:

| Field | Value |
| ------- | ------- |
| Identifier | `trustsky` |
| Name | TrustSky API |
| Scopes | Select all trustsky:* scopes |

### Request Token with Audience

```bash
curl -X POST ${AUTH_ISSUER}/oauth/token \
  -u "${AUTH_CLIENT_ID}:${AUTH_CLIENT_SECRET}" \
  -d "grant_type=client_credentials" \
  -d "scope=trustsky:flight:write" \
  -d "audience=trustsky"
```

### Token Contains Audience Claim

```json
{
  "aud": "trustsky",
  "scope": "trustsky:flight:write trustsky:flight:read",
  "client_id": "...",
  "tenant_id": "..."
}
```

### Validate Audience

APIs should verify the `aud` claim matches the expected identifier:

```go
if claims.Audience != "trustsky" {
    return errors.New("token not intended for this API")
}
```

---

## DPoP (Demonstrating Proof of Possession)

DPoP binds tokens to a specific client key pair, preventing token theft.

### Generate DPoP Proof (Go)

```go
package dpop

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "encoding/base64"
    "time"

    "github.com/golang-jwt/jwt/v5"
    "github.com/google/uuid"
)

type DPoPClient struct {
    privateKey *ecdsa.PrivateKey
}

func NewDPoPClient() (*DPoPClient, error) {
    privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, err
    }
    return &DPoPClient{privateKey: privateKey}, nil
}

func (c *DPoPClient) GenerateProof(method, url string) (string, error) {
    claims := jwt.MapClaims{
        "htm": method,
        "htu": url,
        "jti": uuid.New().String(),
        "iat": time.Now().Unix(),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
    token.Header["typ"] = "dpop+jwt"
    token.Header["jwk"] = map[string]interface{}{
        "kty": "EC",
        "crv": "P-256",
        "x":   base64.RawURLEncoding.EncodeToString(c.privateKey.PublicKey.X.Bytes()),
        "y":   base64.RawURLEncoding.EncodeToString(c.privateKey.PublicKey.Y.Bytes()),
    }

    return token.SignedString(c.privateKey)
}
```

### Token Request with DPoP

```bash
DPOP_PROOF="eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6..."

curl -X POST ${AUTH_ISSUER}/oauth/token \
  -H "DPoP: ${DPOP_PROOF}" \
  -u "${AUTH_CLIENT_ID}:${AUTH_CLIENT_SECRET}" \
  -d "grant_type=client_credentials" \
  -d "scope=trustsky:flight:write"
```

Response:

```json
{
  "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 3600
}
```

### API Request with DPoP

```bash
# Generate new DPoP proof for this request
DPOP_PROOF="eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0..."

curl -X GET https://api.trustsky.example.com/v1/flights \
  -H "Authorization: DPoP ${ACCESS_TOKEN}" \
  -H "DPoP: ${DPOP_PROOF}"
```

---

## Token Revocation

Revoke tokens when they are no longer needed or compromised:

```bash
curl -X POST ${AUTH_ISSUER}/oauth/revoke \
  -u "${AUTH_CLIENT_ID}:${AUTH_CLIENT_SECRET}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=${ACCESS_TOKEN}"
```

Response: `200 OK` (empty body)

---

## Error Responses

### Token Endpoint Errors

| Error | Description |
| ------- | ------------- |
| `invalid_client` | Invalid client_id or client_secret |
| `invalid_grant` | Invalid or expired authorization code |
| `invalid_scope` | Requested scope not allowed for this client |
| `unauthorized_client` | Client not authorized for this grant type |
| `tenant is suspended` | Client's tenant is suspended |
| `tenant is revoked` | Client's tenant is revoked |

Example error response:

```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

### DPoP Errors

| Error                | Description                                     |
|----------------------|-------------------------------------------------|
| `invalid_dpop_proof` | DPoP proof validation failed                    |
| `use_dpop_nonce`     | Server requires nonce (check DPoP-Nonce header) |

---

## Testing & Verification

### Automated Test Script

OryxID includes a test script to verify all integration points:

```bash
# Set credentials
export AUTH_ISSUER=https://localhost:8443
export AUTH_CLIENT_ID=<client-id>
export AUTH_CLIENT_SECRET=<client-secret>

# Run tests
./scripts/test-trustsky-integration.sh
```

Expected output:

```text
========================================
 TrustSky Integration Verification
========================================
Auth Server: https://localhost:8443

[1/7] Testing OIDC Discovery...          PASS
[2/7] Testing JWKS Endpoint...            PASS
[3/7] Testing Token Generation...         PASS
[4/7] Verifying JWT Structure...          PASS
[5/7] Testing Scope Expansion...          PASS
[6/7] Testing Token Introspection...      PASS
[7/7] Testing Token Revocation...         PASS

========================================
 All Tests Passed!
========================================
```

### Manual Verification

```bash
# 1. Check OIDC Discovery
curl ${AUTH_ISSUER}/.well-known/openid-configuration | jq .

# 2. Check JWKS
curl ${AUTH_ISSUER}/.well-known/jwks.json | jq .

# 3. Get token and decode
TOKEN=$(curl -s -X POST ${AUTH_ISSUER}/oauth/token \
  -u "${AUTH_CLIENT_ID}:${AUTH_CLIENT_SECRET}" \
  -d "grant_type=client_credentials" \
  -d "scope=trustsky:flight:write" | jq -r .access_token)

# 4. Decode JWT (paste at jwt.io or use jq)
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

---

## OryxID Admin Setup

> This section is for OryxID administrators setting up TrustSky integration.

### 1. Create TrustSky Scopes

Navigate to **Scopes** in OryxID admin UI and create:

| Scope | Description |
| ------- | ------------- |
| `trustsky:admin` | Full admin access |
| `trustsky:flight:read` | Read flight data |
| `trustsky:flight:write` | Write flight data |
| `trustsky:nfz:read` | Read no-fly zones |
| `trustsky:nfz:write` | Write no-fly zones |
| `trustsky:operator:read` | Read operator data |
| `trustsky:operator:write` | Write operator data |
| `trustsky:telemetry:write` | Write telemetry data |
| `trustsky:sky:read` | Read sky data |

### 2. Create API Resource

Navigate to **API Resources** and create:

| Field | Value |
| ------- | ------- |
| Identifier | `trustsky` |
| Name | TrustSky API |
| Description | TrustSky USSP API |
| Scopes | Select all trustsky:* scopes |

This registers the API and enables the `aud` claim in tokens.

### 3. Create Tenant (if needed)

Navigate to **Tenants** and create:

| Field | Example Value |
| ------- | --------------- |
| Name | Acme Drone Operations |
| Type | `operator` |
| Email | <admin@acme-drones.com> |
| Status | `active` |

### 4. Create Application

Navigate to **Applications** and create:

| Field | Value |
| ------- | ------- |
| Name | TrustSky Backend |
| Client Type | `confidential` |
| Grant Types | `client_credentials` |
| Token Endpoint Auth | `client_secret_basic` |
| Scopes | Select required trustsky:* scopes |
| Tenant | Select tenant (optional) |

### 5. Provide Credentials

After creation, copy and securely provide to TrustSky:

- **Client ID**: UUID format
- **Client Secret**: 64-character secret
- **Issuer URL**: OryxID server URL

---

## Troubleshooting

### Token Request Returns 401

```json
{"error": "invalid_client"}
```

**Causes:**

- Wrong `AUTH_CLIENT_ID` or `AUTH_CLIENT_SECRET`
- Using wrong authentication method (try `-u` instead of form body)

**Fix:**

```bash
# Correct: Basic auth
curl -u "${AUTH_CLIENT_ID}:${AUTH_CLIENT_SECRET}" ...

# Wrong: Form body (unless configured)
curl -d "client_id=${AUTH_CLIENT_ID}&client_secret=${AUTH_CLIENT_SECRET}" ...
```

### Token Request Returns "tenant is suspended"

The tenant associated with the client has been suspended.

**Fix:** Contact OryxID administrator to reactivate the tenant.

### JWT Validation Fails with "Key not found"

JWKS might be cached with old keys.

**Fix:**

- Clear JWKS cache
- Fetch fresh JWKS: `curl ${AUTH_ISSUER}/.well-known/jwks.json`
- Verify `kid` in token matches a key in JWKS

### Scope Not Expanded

Scope hierarchy only works for scopes created in OryxID with proper naming:

- `trustsky:flight:write` expands to include `trustsky:flight:read`
- Custom scopes without `:write`/`:read` suffix don't auto-expand

---

## Integration Checklist

### OryxID Administrator

- [ ] All TrustSky scopes created
- [ ] API Resource created with identifier `trustsky`
- [ ] Tenant created (if multi-tenancy needed)
- [ ] Application created with correct settings
- [ ] Client ID and Secret securely delivered to TrustSky team

### TrustSky Developer

- [ ] Environment variables configured (`AUTH_ISSUER`, `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`)
- [ ] Token generation tested and working
- [ ] Audience claim (`aud`) validated in tokens
- [ ] Token validation implemented (JWKS or introspection)
- [ ] Scope checking implemented in API endpoints
- [ ] Tenant isolation implemented (if multi-tenancy)
- [ ] Token refresh/renewal logic implemented
- [ ] Error handling for auth failures
