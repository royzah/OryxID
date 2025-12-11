# Testing Guide for OryxID

This guide covers testing OryxID's OAuth 2.0 / OIDC implementation, including all supported grant types.

## Prerequisites

### 1. Database Setup

For fresh installations:

```bash
make docker-restart
# or
docker compose down && docker compose up -d
```

For existing databases needing migration:

```bash
docker exec -i oryxid-postgres psql -U oryxid -d oryxid < backend/scripts/migrate_to_jsonb.sql
```

### 2. Ensure Services are Running

```bash
make up
make status
```

## Test Categories

### Unit Tests

Unit tests use SQLite in-memory databases and run without external dependencies:

```bash
# Run all unit tests
make test

# Run specific packages
go test ./internal/handlers/...
go test ./internal/oauth/...
go test ./internal/tokens/...
go test ./internal/middleware/...
go test ./tests/security/...
```

### Integration Tests

Integration tests require running services and a configured test OAuth application.

#### Step 1: Create Test Application

Via Admin Dashboard:
1. Login at http://localhost:8080
2. Navigate to Applications > New Application
3. Configure:
   - Name: Test Application
   - Client Type: confidential
   - Grant Types: Enable all for comprehensive testing
     - authorization_code
     - client_credentials
     - refresh_token
     - device_code
     - token-exchange
     - ciba
   - Redirect URIs: `https://example.com/callback`
   - Scopes: openid, profile, email, offline_access

Or via setup script:

```bash
cd backend
chmod +x scripts/setup_test_app.sh
./scripts/setup_test_app.sh
```

#### Step 2: Configure Environment

```bash
export TEST_CLIENT_ID="<your-client-id>"
export TEST_CLIENT_SECRET="<your-client-secret>"
export API_URL="http://localhost:9000"  # Direct backend, not via nginx
```

#### Step 3: Run Integration Tests

```bash
# Run all integration tests (skip cache)
go test -count=1 -v ./tests/integration/...

# Run specific test
go test -count=1 -v ./tests/integration/... -run TestClientCredentialsFlow
```

### Security Tests

Security tests validate protection against common vulnerabilities:

```bash
go test ./tests/security/...
```

Tests include:
- PKCE implementation correctness
- SQL injection prevention
- XSS protection
- Token replay prevention
- Client authentication timing attack resistance
- Scope escalation prevention
- Redirect URI validation
- Header injection prevention
- Authorization code entropy
- JWT expiration validation

### E2E Tests

End-to-end tests use Playwright:

```bash
# Install dependencies
cd tests/e2e
npm install
npm run install-browsers

# Run tests
npm test              # Headless
npm run test:headed   # With browser visible
npm run test:ui       # Interactive UI mode
npm run test:debug    # Debug mode
```

## Testing OAuth Flows

### Client Credentials Flow

```bash
# Test via curl
curl -X POST http://localhost:9000/oauth/token \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=openid"

# Expected: access_token in response
```

### Authorization Code Flow with PKCE

```bash
# Generate PKCE values
code_verifier=$(openssl rand -base64 32 | tr -d '=/+' | head -c 43)
code_challenge=$(echo -n "$code_verifier" | openssl dgst -sha256 -binary | base64 | tr -d '=/+' | tr '+/' '-_')

# Authorization URL (open in browser or test via integration tests)
echo "http://localhost:8080/oauth/authorize?response_type=code&client_id=$TEST_CLIENT_ID&redirect_uri=https://example.com/callback&code_challenge=$code_challenge&code_challenge_method=S256&scope=openid"
```

### Device Authorization Flow (RFC 8628)

```bash
# 1. Request device code
curl -X POST http://localhost:9000/oauth/device_authorization \
  -d "client_id=$TEST_CLIENT_ID" \
  -d "scope=openid"

# Response contains: device_code, user_code, verification_uri

# 2. User visits verification_uri and enters user_code

# 3. Poll for token
curl -X POST http://localhost:9000/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "device_code=<device_code>" \
  -d "client_id=$TEST_CLIENT_ID"

# Expect: authorization_pending until user authorizes
```

### Token Exchange (RFC 8693)

Requires an existing valid token:

```bash
# First get a token via client credentials
TOKEN=$(curl -s -X POST http://localhost:9000/oauth/token \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "grant_type=client_credentials" \
  -d "scope=openid" | jq -r .access_token)

# Exchange token
curl -X POST http://localhost:9000/oauth/token \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$TOKEN" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=target-service"
```

### CIBA (Client-Initiated Backchannel Authentication)

```bash
# Initiate backchannel auth
curl -X POST http://localhost:9000/oauth/bc-authorize \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "login_hint=admin@example.com" \
  -d "scope=openid" \
  -d "binding_message=Test login"

# Response contains: auth_req_id

# Poll for token
curl -X POST http://localhost:9000/oauth/token \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "grant_type=urn:openid:params:grant-type:ciba" \
  -d "auth_req_id=<auth_req_id>"
```

### Pushed Authorization Requests (RFC 9126)

```bash
# Push authorization request
curl -X POST http://localhost:9000/oauth/par \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "response_type=code" \
  -d "redirect_uri=https://example.com/callback" \
  -d "scope=openid" \
  -d "code_challenge=$code_challenge" \
  -d "code_challenge_method=S256"

# Response contains: request_uri

# Use in authorization (redirect user to):
# /oauth/authorize?client_id=X&request_uri=urn:ietf:params:oauth:request_uri:...
```

### Token Introspection

```bash
curl -X POST http://localhost:9000/oauth/introspect \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "token=$TOKEN"

# Response: active, scope, client_id, exp, etc.
```

### Token Revocation

```bash
curl -X POST http://localhost:9000/oauth/revoke \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "token=$TOKEN"

# Response: 200 OK (empty body on success)
```

## Troubleshooting

### Tests Skip with "Test OAuth application not configured"

The test application credentials are not set. Configure via environment variables:

```bash
export TEST_CLIENT_ID="your-client-id"
export TEST_CLIENT_SECRET="your-client-secret"
export API_URL="http://localhost:9000"
```

### Tests Skip with "CIBA grant type not enabled"

The test application needs CIBA enabled:

1. Edit the test application in the admin dashboard
2. Enable grant type: `urn:openid:params:grant-type:ciba` (CIBA)
3. Save the application

### Health Endpoint Test Fails

The test tries `/health/backend` (JSON) then `/health` (plain text). Ensure nginx is configured correctly with the backend health endpoint.

### Tests Use Cached Results

Run with `-count=1` to bypass test cache:

```bash
go test -count=1 -v ./tests/integration/...
```

### JSONB Serialization Errors

Ensure database uses JSONB types. Check column types:

```sql
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'applications'
AND column_name IN ('grant_types', 'response_types', 'redirect_uris');
```

All should show `jsonb`. If not, run the migration script.

### Application Creation Fails

Check backend logs:

```bash
docker logs oryxid-backend
```

Common causes:
- Database migration not run
- Invalid JSONB format in request

## Test Coverage

Generate coverage report:

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

Or via make:

```bash
make test-coverage
```

## CI/CD Integration

Example GitHub Actions configuration:

```yaml
name: Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - name: Run unit tests
        run: go test ./...

  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:16
        env:
          POSTGRES_USER: oryxid
          POSTGRES_PASSWORD: test
          POSTGRES_DB: oryxid
        ports:
          - 5432:5432
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - name: Run integration tests
        run: go test -v ./tests/integration/...
        env:
          TEST_CLIENT_ID: ${{ secrets.TEST_CLIENT_ID }}
          TEST_CLIENT_SECRET: ${{ secrets.TEST_CLIENT_SECRET }}
          API_URL: http://localhost:9000
```

## Best Practices

1. **Always run unit tests before committing:**
   ```bash
   make test
   ```

2. **Run all tests before merging:**
   ```bash
   make test-all
   ```

3. **Check for race conditions:**
   ```bash
   go test -race ./...
   ```

4. **Use table-driven tests** for multiple scenarios

5. **Clean up test data** in `defer` statements

6. **Use `require` for critical checks**, `assert` for non-critical

7. **Test all OAuth flows** when modifying token handling

8. **Verify PKCE** is properly validated in authorization code flow
