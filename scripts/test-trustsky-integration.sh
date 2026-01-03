#!/bin/bash
# TrustSky Integration Verification Script
# Run this after setting up AUTH_CLIENT_ID and AUTH_CLIENT_SECRET
#
# For trusted SSL (no -k flag needed):
#   make ssl-mkcert && make down && make up
#
# For self-signed SSL (requires -k flag):
#   Set CURL_INSECURE=1 before running this script

set -e

AUTH_ISSUER=${AUTH_ISSUER:-https://localhost:8443}
AUTH_CLIENT_ID=${AUTH_CLIENT_ID:-""}
AUTH_CLIENT_SECRET=${AUTH_CLIENT_SECRET:-""}

# Use -k flag if CURL_INSECURE is set or if using self-signed certs
CURL_OPTS=""
if [ "${CURL_INSECURE:-0}" = "1" ]; then
    CURL_OPTS="-k"
elif [ -f "certs/ssl_cert.pem" ]; then
    # Check if cert is from mkcert (trusted) or self-signed
    if ! curl -s --connect-timeout 2 "$AUTH_ISSUER/.well-known/openid-configuration" > /dev/null 2>&1; then
        echo "Note: Using -k flag for self-signed certificate"
        echo "      Run 'make ssl-mkcert' for trusted local SSL"
        echo ""
        CURL_OPTS="-k"
    fi
fi

if [ -z "$AUTH_CLIENT_ID" ] || [ -z "$AUTH_CLIENT_SECRET" ]; then
    echo "Error: Set AUTH_CLIENT_ID and AUTH_CLIENT_SECRET environment variables"
    echo "Example:"
    echo "  export AUTH_CLIENT_ID=your_client_id"
    echo "  export AUTH_CLIENT_SECRET=your_client_secret"
    exit 1
fi

echo "============================================"
echo "TrustSky USSP Integration Verification"
echo "============================================"
echo ""

# 1. Discovery Endpoint
echo "=== 1. OIDC Discovery Endpoint ==="
echo "GET $AUTH_ISSUER/.well-known/openid-configuration"
DISCOVERY=$(curl -s $CURL_OPTS $AUTH_ISSUER/.well-known/openid-configuration)
if echo "$DISCOVERY" | grep -q "issuer"; then
    echo "[PASS] Discovery endpoint working"
    echo "$DISCOVERY" | python3 -m json.tool 2>/dev/null | head -15
else
    echo "[FAIL] Discovery endpoint not returning expected data"
    echo "$DISCOVERY"
fi
echo ""

# 2. JWKS Endpoint
echo "=== 2. JWKS Endpoint ==="
echo "GET $AUTH_ISSUER/.well-known/jwks.json"
JWKS=$(curl -s $CURL_OPTS $AUTH_ISSUER/.well-known/jwks.json)
if echo "$JWKS" | grep -q "keys"; then
    echo "[PASS] JWKS endpoint working"
    echo "$JWKS" | python3 -m json.tool 2>/dev/null | head -20
else
    echo "[FAIL] JWKS endpoint not returning expected data"
    echo "$JWKS"
fi
echo ""

# 3. Token Endpoint - Basic scope
echo "=== 3. Token Endpoint (Client Credentials) ==="
echo "POST $AUTH_ISSUER/oauth/token"
TOKEN_RESPONSE=$(curl -s $CURL_OPTS -X POST $AUTH_ISSUER/oauth/token \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=trustsky:flight:write" \
  -d "audience=trustsky")

if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
    echo "[PASS] Token endpoint working"
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
    SCOPE=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scope',''))")
    echo "Token type: $(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['token_type'])")"
    echo "Expires in: $(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['expires_in'])")s"
    echo "Scope: $SCOPE"
else
    echo "[FAIL] Token endpoint error"
    echo "$TOKEN_RESPONSE"
    exit 1
fi
echo ""

# 4. Scope Expansion Verification
echo "=== 4. Scope Hierarchy Expansion ==="
if echo "$SCOPE" | grep -q "trustsky:flight:read"; then
    echo "[PASS] Scope expansion working"
    echo "Requested: trustsky:flight:write"
    echo "Received:  $SCOPE"
else
    echo "[FAIL] Scope expansion not working"
    echo "Expected: trustsky:flight:write trustsky:flight:read"
    echo "Got: $SCOPE"
fi
echo ""

# 5. Token Claims Verification
echo "=== 5. Token Claims ==="
# JWT uses base64url encoding - convert to standard base64, add padding, and decode
set +e
JWT_PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d'.' -f2)
# Add padding if needed (base64url omits padding)
MOD=$((${#JWT_PAYLOAD} % 4))
if [ $MOD -eq 2 ]; then JWT_PAYLOAD="${JWT_PAYLOAD}=="; fi
if [ $MOD -eq 3 ]; then JWT_PAYLOAD="${JWT_PAYLOAD}="; fi
PAYLOAD=$(echo "$JWT_PAYLOAD" | tr '_-' '/+' | base64 -d 2>/dev/null)
echo "$PAYLOAD" | python3 -m json.tool 2>/dev/null
set -e

# Check required claims
echo ""
echo "Required TrustSky Claims:"
for claim in iss sub exp iat scope client_id tenant_id; do
    if echo "$PAYLOAD" | grep -q "\"$claim\""; then
        echo "  [PASS] $claim present"
    else
        echo "  [WARN] $claim missing"
    fi
done
echo ""

# 6. Token Introspection
echo "=== 6. Token Introspection ==="
echo "POST $AUTH_ISSUER/oauth/introspect"
INTROSPECT=$(curl -s $CURL_OPTS -X POST $AUTH_ISSUER/oauth/introspect \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN")

if echo "$INTROSPECT" | grep -q '"active":true'; then
    echo "[PASS] Introspection endpoint working"
    echo "$INTROSPECT" | python3 -m json.tool 2>/dev/null
else
    echo "[FAIL] Introspection failed or token inactive"
    echo "$INTROSPECT"
fi
echo ""

# 7. Audience (API Resource) Test
# Disable exit-on-error for this section (audience is optional feature)
set +e
echo "=== 7. Audience Parameter ==="
echo "POST $AUTH_ISSUER/oauth/token (with audience=trustsky)"
AUD_TOKEN_RESPONSE=$(curl -s $CURL_OPTS -X POST $AUTH_ISSUER/oauth/token \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=trustsky:flight:read" \
  -d "audience=trustsky" 2>&1)

if echo "$AUD_TOKEN_RESPONSE" | grep -q "access_token"; then
    AUD_TOKEN=$(echo "$AUD_TOKEN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
    # JWT uses base64url encoding - convert to standard base64 and decode
    AUD_PAYLOAD=$(echo "$AUD_TOKEN" | cut -d'.' -f2 | tr '_-' '/+' | base64 -d 2>/dev/null)
    # aud can be string or array - extract first value if array
    AUD_CLAIM=$(echo "$AUD_PAYLOAD" | python3 -c "import sys,json; d=json.load(sys.stdin); a=d.get('aud',''); print(a[0] if isinstance(a,list) and a else a)" 2>/dev/null || echo "")
    if [ "$AUD_CLAIM" = "trustsky" ]; then
        echo "[PASS] Audience claim present in token"
        echo "aud: $AUD_CLAIM"
    else
        echo "[INFO] Audience claim: $AUD_CLAIM (expected: trustsky)"
        echo "       Ensure API Resource 'trustsky' exists in admin UI"
        echo "       AND application is linked to that API Resource"
    fi
else
    echo "[INFO] Token request with audience returned:"
    echo "$AUD_TOKEN_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$AUD_TOKEN_RESPONSE"
    echo ""
    echo "To enable audience claim:"
    echo "  1. Create API Resource 'TrustSky API' with identifier 'trustsky'"
    echo "  2. Edit application and select 'TrustSky API' under API Resources"
fi
set -e
echo ""

# 8. Admin Scope Expansion
echo "=== 8. Admin Scope Expansion ==="
ADMIN_TOKEN=$(curl -s $CURL_OPTS -X POST $AUTH_ISSUER/oauth/token \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=trustsky:admin")

ADMIN_SCOPE=$(echo "$ADMIN_TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scope',''))" 2>/dev/null)
if echo "$ADMIN_SCOPE" | grep -q "trustsky:flight"; then
    echo "[PASS] Admin scope expands to all trustsky scopes"
    echo "Scope: $ADMIN_SCOPE"
else
    echo "[INFO] Admin scope: $ADMIN_SCOPE"
fi
echo ""

# 9. Token Revocation
echo "=== 9. Token Revocation ==="
echo "POST $AUTH_ISSUER/oauth/revoke"
REVOKE=$(curl -s $CURL_OPTS -X POST $AUTH_ISSUER/oauth/revoke \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN")

# Check if token is now inactive
INTROSPECT_AFTER=$(curl -s $CURL_OPTS -X POST $AUTH_ISSUER/oauth/introspect \
  -u "$AUTH_CLIENT_ID:$AUTH_CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN")

if echo "$INTROSPECT_AFTER" | grep -q '"active":false'; then
    echo "[PASS] Token revocation working"
else
    echo "[INFO] Revocation response: Token may still be cached"
fi
echo ""

echo "============================================"
echo "Verification Complete"
echo "============================================"
