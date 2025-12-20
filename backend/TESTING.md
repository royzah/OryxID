# Testing

Testing guide for OryxID backend. See [Backend README](./README.md) for API reference.

## Quick Start

```bash
make test              # All tests
make test-backend      # Backend only
make test-coverage     # With coverage report
```

## Test Categories

### Unit Tests

No external dependencies required (uses in-memory SQLite):

```bash
go test ./internal/handlers/...
go test ./internal/oauth/...
go test ./internal/tokens/...
go test ./internal/middleware/...
```

### Security Tests

```bash
go test ./tests/security/...
```

Covers:

- PKCE validation
- SQL injection prevention
- Token replay attacks
- Timing attack resistance
- Scope escalation
- Redirect URI validation

### Integration Tests

Requires running services:

```bash
# 1. Start services
make up

# 2. Create test application via admin UI or script
./scripts/setup_test_app.sh

# 3. Set environment
export TEST_CLIENT_ID="your-client-id"
export TEST_CLIENT_SECRET="your-secret"
export API_URL="http://localhost:9000"

# 4. Run tests
go test -count=1 -v ./tests/integration/...
```

## Testing OAuth Flows

### Client Credentials

```bash
curl -X POST http://localhost:9000/oauth/token \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=openid"
```

### Authorization Code with PKCE

```bash
# Generate PKCE
verifier=$(openssl rand -base64 32 | tr -d '=/+' | head -c 43)
challenge=$(echo -n "$verifier" | openssl dgst -sha256 -binary | base64 | tr -d '=/+' | tr '+/' '-_')

# Authorization URL
echo "http://localhost:8080/oauth/authorize?response_type=code&client_id=$TEST_CLIENT_ID&redirect_uri=https://example.com/callback&code_challenge=$challenge&code_challenge_method=S256"

# Exchange code
curl -X POST http://localhost:9000/oauth/token \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://example.com/callback&client_id=$TEST_CLIENT_ID&code_verifier=$verifier"
```

### Device Flow

```bash
# Request device code
curl -X POST http://localhost:9000/oauth/device_authorization \
  -d "client_id=$TEST_CLIENT_ID&scope=openid"

# Poll for token (after user authorizes)
curl -X POST http://localhost:9000/oauth/token \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=DEVICE_CODE&client_id=$TEST_CLIENT_ID"
```

### Token Exchange

```bash
# Get initial token
TOKEN=$(curl -s -X POST http://localhost:9000/oauth/token \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "grant_type=client_credentials" | jq -r .access_token)

# Exchange
curl -X POST http://localhost:9000/oauth/token \
  -u "$TEST_CLIENT_ID:$TEST_CLIENT_SECRET" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=$TOKEN&subject_token_type=urn:ietf:params:oauth:token-type:access_token"
```

## Coverage

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

## CI/CD

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
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
      - run: go test ./...
```

## Troubleshooting

| Issue | Solution |
| ------- | ---------- |
| Tests skip with "not configured" | Set `TEST_CLIENT_ID`, `TEST_CLIENT_SECRET`, `API_URL` |
| Cached results | Use `go test -count=1` |
| JSONB errors | Run database migration script |
