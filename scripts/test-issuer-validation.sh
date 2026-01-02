#!/bin/bash
# Test OAuth Issuer URL Validation
# Verifies that AUTH_ISSUER and AUTH_JWKS_URL work with a single base URL

set -e

AUTH_ISSUER="https://localhost:8443"
AUTH_JWKS_URL="https://localhost:8443/.well-known/jwks.json"

echo "============================================"
echo "OAuth Issuer URL Validation Test"
echo "============================================"
echo ""
echo "Configuration:"
echo "  AUTH_ISSUER:   $AUTH_ISSUER"
echo "  AUTH_JWKS_URL: $AUTH_JWKS_URL"
echo ""

# 1. Get OIDC Discovery
echo "=== 1. Verify OIDC Discovery Issuer ==="
DISCOVERY=$(curl -sk "$AUTH_ISSUER/.well-known/openid-configuration")
DISCOVERY_ISSUER=$(echo "$DISCOVERY" | jq -r '.issuer')
DISCOVERY_JWKS=$(echo "$DISCOVERY" | jq -r '.jwks_uri')

echo "Discovery issuer:   $DISCOVERY_ISSUER"
echo "Discovery jwks_uri: $DISCOVERY_JWKS"

if [ "$DISCOVERY_ISSUER" = "$AUTH_ISSUER" ]; then
    echo "[PASS] Discovery issuer matches AUTH_ISSUER"
else
    echo "[FAIL] Discovery issuer mismatch!"
    echo "  Expected: $AUTH_ISSUER"
    echo "  Got:      $DISCOVERY_ISSUER"
    exit 1
fi

# 2. Fetch JWKS from AUTH_JWKS_URL
echo ""
echo "=== 2. Fetch JWKS from AUTH_JWKS_URL ==="
JWKS=$(curl -sk "$AUTH_JWKS_URL")
KEY_COUNT=$(echo "$JWKS" | jq '.keys | length')
JWKS_KID=$(echo "$JWKS" | jq -r '.keys[0].kid')

echo "JWKS keys count: $KEY_COUNT"
echo "Key ID (kid):    $JWKS_KID"

if [ "$KEY_COUNT" -gt 0 ]; then
    echo "[PASS] JWKS endpoint returns keys"
else
    echo "[FAIL] No keys found in JWKS!"
    exit 1
fi

# 3. Get a token using the TrustSky client
echo ""
echo "=== 3. Get Access Token ==="

# Get client credentials from stored file or database
if [ -f "/tmp/trustsky_client.txt" ]; then
    source /tmp/trustsky_client.txt
    CLIENT_ID=$TRUSTSKY_CLIENT_ID
    CLIENT_SECRET=$TRUSTSKY_CLIENT_SECRET
else
    # Try to get from docker
    CLIENT_ID=$(docker exec oryxid-postgres-1 psql -U oryxid -d oryxid -t -c \
        "SELECT client_id FROM applications WHERE name = 'TrustSky USSP' LIMIT 1;" 2>/dev/null | tr -d ' \n')
    CLIENT_SECRET=$(docker exec oryxid-postgres-1 psql -U oryxid -d oryxid -t -c \
        "SELECT client_secret FROM applications WHERE name = 'TrustSky USSP' LIMIT 1;" 2>/dev/null | tr -d ' \n')
fi

if [ -z "$CLIENT_ID" ] || [ -z "$CLIENT_SECRET" ]; then
    echo "[ERROR] Could not find TrustSky client credentials"
    echo "Please set TRUSTSKY_CLIENT_ID and TRUSTSKY_CLIENT_SECRET"
    exit 1
fi

echo "Using client: $CLIENT_ID"

TOKEN_RESP=$(curl -sk -X POST "$AUTH_ISSUER/oauth/token" \
    -u "$CLIENT_ID:$CLIENT_SECRET" \
    -d "grant_type=client_credentials&audience=trustsky&scope=trustsky:flight:read")

ACCESS_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.access_token')

if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
    echo "[FAIL] Could not get access token"
    echo "Response: $TOKEN_RESP"
    exit 1
fi

echo "[PASS] Got access token"

# 4. Decode and validate token issuer
echo ""
echo "=== 4. Validate Token Issuer Claim ==="

# Decode JWT header and payload
HEADER=$(echo "$ACCESS_TOKEN" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null)
PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null)

TOKEN_ISS=$(echo "$PAYLOAD" | jq -r '.iss')
TOKEN_AUD=$(echo "$PAYLOAD" | jq -r '.aud[0]')
TOKEN_KID=$(echo "$HEADER" | jq -r '.kid')

echo "Token issuer (iss): $TOKEN_ISS"
echo "Token audience:     $TOKEN_AUD"
echo "Token key ID (kid): $TOKEN_KID"

if [ "$TOKEN_ISS" = "$AUTH_ISSUER" ]; then
    echo "[PASS] Token issuer matches AUTH_ISSUER"
else
    echo "[FAIL] Token issuer mismatch!"
    echo "  Expected: $AUTH_ISSUER"
    echo "  Got:      $TOKEN_ISS"
    exit 1
fi

# 5. Verify kid matches JWKS
echo ""
echo "=== 5. Verify Token kid Matches JWKS ==="

if [ "$TOKEN_KID" = "$JWKS_KID" ]; then
    echo "[PASS] Token kid matches JWKS kid: $TOKEN_KID"
else
    echo "[FAIL] Token kid mismatch!"
    echo "  Token kid: $TOKEN_KID"
    echo "  JWKS kid:  $JWKS_KID"
    exit 1
fi

# 6. Verify token can be introspected
echo ""
echo "=== 6. Introspect Token at Issuer ==="

INTROSPECT=$(curl -sk -X POST "$AUTH_ISSUER/oauth/introspect" \
    -u "$CLIENT_ID:$CLIENT_SECRET" \
    -d "token=$ACCESS_TOKEN")

ACTIVE=$(echo "$INTROSPECT" | jq -r '.active')
INTRO_ISS=$(echo "$INTROSPECT" | jq -r '.iss')

echo "Token active:     $ACTIVE"
echo "Introspect iss:   $INTRO_ISS"

if [ "$ACTIVE" = "true" ]; then
    echo "[PASS] Token is active"
else
    echo "[FAIL] Token introspection failed"
    exit 1
fi

if [ "$INTRO_ISS" = "$AUTH_ISSUER" ]; then
    echo "[PASS] Introspection issuer matches AUTH_ISSUER"
fi

echo ""
echo "============================================"
echo "All Validation Tests Passed!"
echo "============================================"
echo ""
echo "Summary:"
echo "  ✓ OIDC Discovery returns correct issuer: $AUTH_ISSUER"
echo "  ✓ JWKS available at: $AUTH_JWKS_URL"
echo "  ✓ JWT tokens contain iss: $AUTH_ISSUER"
echo "  ✓ Token kid matches JWKS kid: $TOKEN_KID"
echo "  ✓ Token introspection works"
echo ""
echo "TrustSky USSP can now use a single configuration:"
echo ""
echo "  AUTH_ISSUER=$AUTH_ISSUER"
echo "  AUTH_JWKS_URL=$AUTH_JWKS_URL"
echo ""
