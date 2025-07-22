#!/bin/bash

# OryxID OAuth2 Flow Test Script
# This script demonstrates various OAuth2 flows

set -e

# Configuration
BASE_URL="${BASE_URL:-http://localhost:9000}"
CLIENT_ID="${CLIENT_ID:-test-client-id}"
CLIENT_SECRET="${CLIENT_SECRET:-test-client-secret}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:8080/callback}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}OryxID OAuth2 Test Script${NC}"
echo "========================="
echo "Base URL: $BASE_URL"
echo ""

# Function to test endpoint
test_endpoint() {
    local method=$1
    local endpoint=$2
    local data=$3
    local expected_status=$4
    local description=$5
    
    echo -e "${YELLOW}Testing: $description${NC}"
    echo "Endpoint: $method $endpoint"
    
    if [ "$method" == "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$BASE_URL$endpoint")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "$data" \
            "$BASE_URL$endpoint")
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    if [ "$http_code" == "$expected_status" ]; then
        echo -e "${GREEN}✓ Status: $http_code (Expected: $expected_status)${NC}"
        echo "Response: $body" | jq '.' 2>/dev/null || echo "$body"
    else
        echo -e "${RED}✗ Status: $http_code (Expected: $expected_status)${NC}"
        echo "Response: $body"
    fi
    echo ""
}

# Test 1: OpenID Connect Discovery
test_endpoint "GET" "/.well-known/openid-configuration" "" "200" "OpenID Connect Discovery"

# Test 2: JWKS Endpoint
test_endpoint "GET" "/.well-known/jwks.json" "" "200" "JWKS Endpoint"

# Test 3: Client Credentials Grant
echo -e "${YELLOW}Testing: Client Credentials Grant${NC}"
echo "Endpoint: POST /oauth/token"

token_response=$(curl -s -X POST "$BASE_URL/oauth/token" \
    -u "$CLIENT_ID:$CLIENT_SECRET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials&scope=read write")

echo "$token_response" | jq '.' 2>/dev/null || echo "$token_response"

# Extract access token
ACCESS_TOKEN=$(echo "$token_response" | jq -r '.access_token' 2>/dev/null)

if [ ! -z "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
    echo -e "${GREEN}✓ Successfully obtained access token${NC}"
    echo ""
    
    # Test 4: Token Introspection
    echo -e "${YELLOW}Testing: Token Introspection${NC}"
    echo "Endpoint: POST /oauth/introspect"
    
    introspect_response=$(curl -s -X POST "$BASE_URL/oauth/introspect" \
        -u "$CLIENT_ID:$CLIENT_SECRET" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "token=$ACCESS_TOKEN")
    
    echo "$introspect_response" | jq '.' 2>/dev/null || echo "$introspect_response"
    echo ""
    
    # Test 5: Use token to access protected resource
    echo -e "${YELLOW}Testing: Protected Resource Access${NC}"
    echo "Endpoint: GET /api/v1/applications"
    
    api_response=$(curl -s -w "\n%{http_code}" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        "$BASE_URL/api/v1/applications")
    
    http_code=$(echo "$api_response" | tail -n1)
    body=$(echo "$api_response" | sed '$d')
    
    if [ "$http_code" == "200" ]; then
        echo -e "${GREEN}✓ Successfully accessed protected resource${NC}"
    else
        echo -e "${RED}✗ Failed to access protected resource (Status: $http_code)${NC}"
    fi
    echo "Response: $body" | jq '.' 2>/dev/null || echo "$body"
else
    echo -e "${RED}✗ Failed to obtain access token${NC}"
fi

echo ""
echo -e "${GREEN}Test completed!${NC}"

# Optional: Test Authorization Code Flow (requires user interaction)
echo ""
echo "To test the Authorization Code flow, visit:"
echo "$BASE_URL/oauth/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid profile email&state=test123"