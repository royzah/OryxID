#!/bin/bash

# Script to create test OAuth application for integration tests
# Usage: ./scripts/setup_test_app.sh

set -e

API_URL="${API_URL:-http://localhost:9000}"
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin123}"

echo "Setting up test OAuth application..."

# 1. Login as admin to get token
echo "Logging in as admin..."
TOKEN=$(curl -s -X POST "${API_URL}/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${ADMIN_USERNAME}\",\"password\":\"${ADMIN_PASSWORD}\"}" | jq -r '.token')

if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
  echo "Error: Failed to login. Please check your credentials and API_URL."
  exit 1
fi

echo "Successfully logged in."

# 2. Create test application
echo "Creating test application..."
RESPONSE=$(curl -s -X POST "${API_URL}/api/v1/applications" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Application",
    "description": "Application for integration tests",
    "client_type": "confidential",
    "grant_types": ["client_credentials", "authorization_code", "refresh_token"],
    "response_types": ["code"],
    "redirect_uris": ["https://example.com/callback", "http://localhost:3000/callback"]
  }')

# Check if creation was successful
if echo "$RESPONSE" | jq -e '.error' > /dev/null; then
  echo "Error creating application:"
  echo "$RESPONSE" | jq '.error'
  exit 1
fi

# Extract client_id and client_secret
CLIENT_ID=$(echo "$RESPONSE" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$RESPONSE" | jq -r '.client_secret')

if [ "$CLIENT_ID" == "null" ] || [ -z "$CLIENT_ID" ]; then
  echo "Error: Failed to create application. Response:"
  echo "$RESPONSE" | jq '.'
  exit 1
fi

echo ""
echo "✅ Test application created successfully!"
echo ""
echo "Application Details:"
echo "===================="
echo "Client ID:     $CLIENT_ID"
echo "Client Secret: $CLIENT_SECRET"
echo ""
echo "To use in integration tests, set these environment variables:"
echo ""
echo "export TEST_CLIENT_ID=\"$CLIENT_ID\""
echo "export TEST_CLIENT_SECRET=\"$CLIENT_SECRET\""
echo ""
echo "Or update tests/integration/oauth_flow_test.go with these values."
