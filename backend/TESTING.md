# Testing Guide for OryxID

This guide explains how to properly test OryxID after the JSONB refactoring.

## Prerequisites

1. **Migrate Existing Database** (if you have an existing database)

   If you're upgrading from an older version that used `TEXT[]` arrays, you need to run the migration:

   ```bash
   # Connect to your PostgreSQL database and run:
   psql -U your_user -d oryxid -f backend/scripts/migrate_to_jsonb.sql
   ```

   Or if using Docker:
   ```bash
   docker exec -i oryxid-postgres psql -U oryxid -d oryxid < backend/scripts/migrate_to_jsonb.sql
   ```

2. **Fresh Database Setup**

   If you're starting fresh, just restart your services:

   ```bash
   make docker-restart
   # or
   docker-compose down && docker-compose up -d
   ```

## Running Tests

### 1. Unit Tests

Unit tests use SQLite in-memory databases and should work without any setup:

```bash
# Run all unit tests
make test

# Run specific package tests
go test ./internal/handlers/...
go test ./internal/oauth/...
go test ./tests/security/...
```

### 2. Integration Tests

Integration tests require a test OAuth application to be created in the running database.

**Step 1: Ensure your backend is running**
```bash
make dev
# or
docker-compose up -d
```

**Step 2: Run the setup script**
```bash
cd backend
chmod +x scripts/setup_test_app.sh
./scripts/setup_test_app.sh
```

This will:
- Login as admin
- Create a test application
- Display the client_id and client_secret

**Step 3: Update test configuration**

Either set environment variables:
```bash
export TEST_CLIENT_ID="<client-id-from-script>"
export TEST_CLIENT_SECRET="<client-secret-from-script>"
```

Or update the test file `tests/integration/oauth_flow_test.go`:
```go
const (
    testClientID     = "<your-client-id>"
    testClientSecret = "<your-client-secret>"
)
```

**Step 4: Run integration tests**
```bash
make test-integration
```

### 3. Security Tests

Security tests are automatically run with unit tests:

```bash
go test ./tests/security/...
```

These tests verify:
- PKCE implementation
- SQL injection prevention
- XSS protection
- Token replay prevention
- Client authentication timing attack resistance
- Scope escalation prevention
- Redirect URI validation
- Header injection prevention
- Authorization code entropy
- JWT expiration

### 4. E2E Tests

E2E tests require Playwright to be installed. First install dependencies:

```bash
cd tests/e2e
npm install
npm run install-browsers
```

Or if you prefer, install system dependencies too:
```bash
sudo npx playwright install-deps  # Linux only, installs system packages
```

Then run:
```bash
cd ../..  # Return to project root
make test-e2e
```

Or run tests directly:
```bash
cd tests/e2e
npm test              # Run all tests headless
npm run test:headed   # Run with browser visible
npm run test:ui       # Run in UI mode for debugging
npm run test:debug    # Run in debug mode
```

## Troubleshooting

### Application Creation Fails

**Error:** `{"error":"Failed to create application"}`

**Solutions:**

1. **Check if migration was run:**
   ```sql
   -- Connect to PostgreSQL and check column types:
   SELECT column_name, data_type
   FROM information_schema.columns
   WHERE table_name = 'applications'
   AND column_name IN ('grant_types', 'response_types', 'redirect_uris');
   ```

   Should return `jsonb` for all three. If it shows `ARRAY`, run the migration script.

2. **Check backend logs:**
   ```bash
   docker logs oryxid-backend
   # or if running locally:
   tail -f logs/backend.log
   ```

3. **Recreate database (DESTRUCTIVE):**
   ```bash
   docker-compose down -v
   docker-compose up -d
   ```

### "no such table: audit_logs" in Tests

This has been fixed in the latest version. If you still see it:

1. Pull latest changes
2. Ensure `database.AuditLog{}` is in the AutoMigrate list in your test setup

### Integration Tests Skip

**Message:** `Test OAuth application not configured`

**Solution:** The integration tests need valid OAuth client credentials. You have two options:

**Option 1 - Use Environment Variables (Recommended):**

1. Run the setup script to create a test application:
   ```bash
   ./backend/scripts/setup_test_app.sh
   ```

2. Export the credentials shown by the script:
   ```bash
   export TEST_CLIENT_ID="<client-id-from-script>"
   export TEST_CLIENT_SECRET="<client-secret-from-script>"
   ```

3. Run the tests:
   ```bash
   make test-integration
   ```

**Option 2 - Use Hardcoded Values:**

Manually create an application with these exact credentials:
- Client ID: `test-client-id`
- Client Secret: `test-secret` (plaintext, will be hashed)
- Grant Types: `client_credentials`, `authorization_code`, `refresh_token`
- Redirect URIs: `https://example.com/callback`

Then run tests without environment variables.

### E2E Tests Fail

**Error:** `Cannot find module '@playwright/test'`

**Solution:** Install the npm dependencies in the e2e directory:

```bash
cd tests/e2e
npm install
npm run install-browsers
```

The package.json was added in the latest version. If you don't see it, pull the latest changes.

### JSONB Serialization Errors

**Error:** `sql: converting argument type: unsupported type map[string]interface{}`

**Solution:** This was fixed by using the custom `JSONB` type. Ensure you're on the latest version:

```go
// In model.go, Metadata fields should use JSONB type:
Metadata JSONB `gorm:"type:jsonb" json:"metadata,omitempty"`

// NOT:
Metadata map[string]interface{} `gorm:"type:jsonb"`
```

## Test Coverage

Run with coverage report:

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
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

## Continuous Integration

For CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: |
    make test
    make test-integration
  env:
    TEST_CLIENT_ID: ${{ secrets.TEST_CLIENT_ID }}
    TEST_CLIENT_SECRET: ${{ secrets.TEST_CLIENT_SECRET }}
```
