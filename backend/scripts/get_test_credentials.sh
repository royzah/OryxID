#!/bin/bash

# Script to get or create test OAuth application credentials for integration tests
# Usage: source ./scripts/get_test_credentials.sh
#        or: eval $(./scripts/get_test_credentials.sh)

set -e

API_URL="${API_URL:-http://localhost:9000}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin123}"
CACHE_FILE="/tmp/.oryxid_test_credentials"

# Check if we have cached credentials that are still valid
if [ -f "$CACHE_FILE" ]; then
    source "$CACHE_FILE"

    # Verify credentials are still valid
    RESPONSE=$(curl -s -X POST "${API_URL}/oauth/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&scope=openid" \
        -u "${TEST_CLIENT_ID}:${TEST_CLIENT_SECRET}" 2>/dev/null || echo "")

    if echo "$RESPONSE" | grep -q "access_token"; then
        # Credentials are valid, export them
        echo "export TEST_CLIENT_ID=\"${TEST_CLIENT_ID}\""
        echo "export TEST_CLIENT_SECRET=\"${TEST_CLIENT_SECRET}\""
        exit 0
    fi
fi

# Credentials not cached or invalid, create new test application
>&2 echo "Creating new test application..."

# Login as admin
TOKEN=$(curl -s -X POST "${API_URL}/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USERNAME}\",\"password\":\"${ADMIN_PASSWORD}\"}" 2>/dev/null | jq -r '.token' 2>/dev/null || echo "")

if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
    >&2 echo "Error: Failed to login as admin. Please ensure the server is running."
    exit 1
fi

# Create test application
RESPONSE=$(curl -s -X POST "${API_URL}/api/v1/applications" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Integration Test Application",
        "description": "Auto-created for integration tests",
        "client_type": "confidential",
        "grant_types": ["client_credentials", "authorization_code", "refresh_token"],
        "response_types": ["code"],
        "redirect_uris": ["https://example.com/callback", "http://localhost:3000/callback"]
    }' 2>/dev/null)

# Extract credentials
TEST_CLIENT_ID=$(echo "$RESPONSE" | jq -r '.client_id' 2>/dev/null || echo "")
TEST_CLIENT_SECRET=$(echo "$RESPONSE" | jq -r '.client_secret' 2>/dev/null || echo "")

if [ "$TEST_CLIENT_ID" == "null" ] || [ -z "$TEST_CLIENT_ID" ]; then
    >&2 echo "Error: Failed to create test application."
    >&2 echo "Response: $RESPONSE"
    exit 1
fi

# Cache credentials
cat > "$CACHE_FILE" <<EOF
TEST_CLIENT_ID="${TEST_CLIENT_ID}"
TEST_CLIENT_SECRET="${TEST_CLIENT_SECRET}"
EOF

>&2 echo "✅ Test application created successfully"

# Output export commands
echo "export TEST_CLIENT_ID=\"${TEST_CLIENT_ID}\""
echo "export TEST_CLIENT_SECRET=\"${TEST_CLIENT_SECRET}\""
