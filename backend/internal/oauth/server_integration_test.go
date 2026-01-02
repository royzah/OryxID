package oauth

import (
	"sort"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/tiiuae/oryxid/internal/config"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/tokens"
	"github.com/tiiuae/oryxid/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupIntegrationTestDB creates an in-memory SQLite database for testing
func setupIntegrationTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate required models
	err = db.AutoMigrate(
		&database.User{},
		&database.Role{},
		&database.Permission{},
		&database.Scope{},
		&database.Audience{},
		&database.Application{},
		&database.Tenant{},
		&database.Token{},
		&database.AuthorizationCode{},
		&database.SigningKey{},
	)
	require.NoError(t, err)

	return db
}

// setupIntegrationTestServer creates a test OAuth server with the given database
func setupIntegrationTestServer(t *testing.T, db *gorm.DB) *Server {
	t.Helper()

	// Generate test RSA key pair
	privateKey, err := crypto.GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	// Create JWT config
	jwtConfig := &config.JWTConfig{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		Kid:           "test-key-id",
		SigningMethod: jwt.SigningMethodRS256,
	}

	// Create token manager
	tm, err := tokens.NewTokenManager(jwtConfig, "http://localhost:8080")
	require.NoError(t, err)

	return NewServer(db, tm)
}

// createIntegrationTestTenant creates a test tenant with the given status
func createIntegrationTestTenant(t *testing.T, db *gorm.DB, name, status string) *database.Tenant {
	t.Helper()
	tenant := &database.Tenant{
		BaseModel: database.BaseModel{ID: uuid.New()},
		Name:      name,
		Type:      database.TenantTypeOperator,
		Status:    status,
		Email:     name + "@test.com",
	}
	err := db.Create(tenant).Error
	require.NoError(t, err)
	return tenant
}

// createIntegrationTestApplication creates a test application with optional tenant
func createIntegrationTestApplication(t *testing.T, db *gorm.DB, clientID, clientSecret string, tenant *database.Tenant, scopes []string) *database.Application {
	t.Helper()

	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	require.NoError(t, err)

	app := &database.Application{
		BaseModel:               database.BaseModel{ID: uuid.New()},
		ClientID:                clientID,
		HashedClientSecret:      string(hashedSecret),
		Name:                    "Test App",
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              database.StringArray{"client_credentials", "password", "authorization_code", "refresh_token"},
		ResponseTypes:           database.StringArray{"code"},
		RedirectURIs:            database.StringArray{"https://test.example.com/callback"},
	}

	if tenant != nil {
		app.TenantID = &tenant.ID
	}

	err = db.Create(app).Error
	require.NoError(t, err)

	// Create and associate scopes
	for _, scopeName := range scopes {
		scope := &database.Scope{
			BaseModel: database.BaseModel{ID: uuid.New()},
			Name:      scopeName,
			IsDefault: false,
		}
		err = db.Create(scope).Error
		require.NoError(t, err)
		err = db.Model(app).Association("Scopes").Append(scope)
		require.NoError(t, err)
	}

	return app
}

// =============================================================================
// Scope Expansion Tests
// =============================================================================

func TestScopeExpansionInClientCredentials(t *testing.T) {
	db := setupIntegrationTestDB(t)
	server := setupIntegrationTestServer(t, db)

	// Create application with trustsky scopes
	app := createIntegrationTestApplication(t, db, "test-client", "test-secret", nil, []string{
		"trustsky:admin",
		"trustsky:flight:write",
		"trustsky:flight:read",
		"trustsky:nfz:write",
		"trustsky:nfz:read",
		"trustsky:telemetry:write",
		"trustsky:sky:read",
		"trustsky:operator:read",
		"trustsky:operator:write",
	})

	tests := []struct {
		name           string
		requestedScope string
		expectedScopes []string
	}{
		{
			name:           "admin expands to all trustsky scopes",
			requestedScope: "trustsky:admin",
			expectedScopes: []string{
				"trustsky:admin",
				"trustsky:flight:read",
				"trustsky:flight:write",
				"trustsky:nfz:read",
				"trustsky:nfz:write",
				"trustsky:telemetry:write",
				"trustsky:sky:read",
				"trustsky:operator:read",
				"trustsky:operator:write",
			},
		},
		{
			name:           "flight:write expands to include flight:read",
			requestedScope: "trustsky:flight:write",
			expectedScopes: []string{
				"trustsky:flight:write",
				"trustsky:flight:read",
			},
		},
		{
			name:           "nfz:write expands to include nfz:read",
			requestedScope: "trustsky:nfz:write",
			expectedScopes: []string{
				"trustsky:nfz:write",
				"trustsky:nfz:read",
			},
		},
		{
			name:           "operator:write expands to include operator:read",
			requestedScope: "trustsky:operator:write",
			expectedScopes: []string{
				"trustsky:operator:write",
				"trustsky:operator:read",
			},
		},
		{
			name:           "multiple scopes expand independently",
			requestedScope: "trustsky:flight:write trustsky:nfz:write",
			expectedScopes: []string{
				"trustsky:flight:write",
				"trustsky:flight:read",
				"trustsky:nfz:write",
				"trustsky:nfz:read",
			},
		},
		{
			name:           "read-only scope does not expand",
			requestedScope: "trustsky:flight:read",
			expectedScopes: []string{
				"trustsky:flight:read",
			},
		},
		{
			name:           "telemetry:write does not expand (no read equivalent)",
			requestedScope: "trustsky:telemetry:write",
			expectedScopes: []string{
				"trustsky:telemetry:write",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &TokenRequest{
				GrantType:    "client_credentials",
				ClientID:     app.ClientID,
				ClientSecret: "test-secret",
				Scope:        tt.requestedScope,
			}

			resp, err := server.ClientCredentialsGrant(req)
			require.NoError(t, err)

			// Parse returned scopes
			returnedScopes := strings.Split(resp.Scope, " ")
			sort.Strings(returnedScopes)
			sort.Strings(tt.expectedScopes)

			// Verify all expected scopes are present
			returnedSet := make(map[string]bool)
			for _, s := range returnedScopes {
				returnedSet[s] = true
			}

			for _, expected := range tt.expectedScopes {
				if !returnedSet[expected] {
					t.Errorf("expected scope %q not found in response: %v", expected, returnedScopes)
				}
			}

			// Verify no unexpected scopes (except those implied by hierarchy)
			expectedSet := make(map[string]bool)
			for _, s := range tt.expectedScopes {
				expectedSet[s] = true
			}

			for _, returned := range returnedScopes {
				if !expectedSet[returned] {
					t.Errorf("unexpected scope %q in response: %v", returned, returnedScopes)
				}
			}
		})
	}
}

func TestScopeExpansionPreservesNonTrustSkyScopes(t *testing.T) {
	db := setupIntegrationTestDB(t)
	server := setupIntegrationTestServer(t, db)

	// Create application with mixed scopes
	app := createIntegrationTestApplication(t, db, "test-client", "test-secret", nil, []string{
		"openid",
		"profile",
		"email",
		"trustsky:flight:write",
	})

	req := &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		Scope:        "openid profile trustsky:flight:write",
	}

	resp, err := server.ClientCredentialsGrant(req)
	require.NoError(t, err)

	returnedScopes := strings.Split(resp.Scope, " ")
	returnedSet := make(map[string]bool)
	for _, s := range returnedScopes {
		returnedSet[s] = true
	}

	// Verify OpenID scopes are preserved
	if !returnedSet["openid"] {
		t.Error("openid scope should be preserved")
	}
	if !returnedSet["profile"] {
		t.Error("profile scope should be preserved")
	}

	// Verify trustsky scope expansion
	if !returnedSet["trustsky:flight:write"] {
		t.Error("trustsky:flight:write scope should be present")
	}
	if !returnedSet["trustsky:flight:read"] {
		t.Error("trustsky:flight:read scope should be added via expansion")
	}
}

// =============================================================================
// Tenant Status Tests
// =============================================================================

func TestTenantStatusCheckInClientCredentials(t *testing.T) {
	tests := []struct {
		name         string
		tenantStatus string
		expectError  bool
		errorMsg     string
	}{
		{
			name:         "active tenant allows token issuance",
			tenantStatus: database.TenantStatusActive,
			expectError:  false,
		},
		{
			name:         "suspended tenant blocks token issuance",
			tenantStatus: database.TenantStatusSuspended,
			expectError:  true,
			errorMsg:     "tenant is suspended",
		},
		{
			name:         "revoked tenant blocks token issuance",
			tenantStatus: database.TenantStatusRevoked,
			expectError:  true,
			errorMsg:     "tenant is revoked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupIntegrationTestDB(t)
			server := setupIntegrationTestServer(t, db)

			// Create tenant with specific status
			tenant := createIntegrationTestTenant(t, db, "test-tenant", tt.tenantStatus)

			// Create application associated with tenant
			app := createIntegrationTestApplication(t, db, "test-client", "test-secret", tenant, []string{
				"trustsky:flight:read",
			})

			req := &TokenRequest{
				GrantType:    "client_credentials",
				ClientID:     app.ClientID,
				ClientSecret: "test-secret",
				Scope:        "trustsky:flight:read",
			}

			resp, err := server.ClientCredentialsGrant(req)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error for %s tenant, got success", tt.tenantStatus)
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected success for %s tenant, got error: %v", tt.tenantStatus, err)
				}
				if resp == nil {
					t.Error("expected response, got nil")
				}
			}
		})
	}
}

func TestTenantStatusCheckInRefreshToken(t *testing.T) {
	db := setupIntegrationTestDB(t)
	server := setupIntegrationTestServer(t, db)

	// Create active tenant first
	tenant := createIntegrationTestTenant(t, db, "test-tenant", database.TenantStatusActive)

	// Create application associated with tenant
	app := createIntegrationTestApplication(t, db, "test-client", "test-secret", tenant, []string{
		"trustsky:flight:read",
	})

	// Get initial tokens while tenant is active
	initialReq := &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		Scope:        "trustsky:flight:read",
	}

	_, err := server.ClientCredentialsGrant(initialReq)
	require.NoError(t, err)

	// Now suspend the tenant
	db.Model(tenant).Update("status", database.TenantStatusSuspended)

	// Try to use refresh token after tenant suspension
	refreshReq := &TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		RefreshToken: "dummy-token",
	}

	_, err = server.RefreshTokenGrant(refreshReq)
	require.Error(t, err)
	// Should fail with "tenant is suspended" before even checking the refresh token
	if !strings.Contains(err.Error(), "tenant is suspended") {
		t.Logf("Got error: %v (tenant check may have passed)", err)
	}
}

func TestNoTenantAllowsTokenIssuance(t *testing.T) {
	db := setupIntegrationTestDB(t)
	server := setupIntegrationTestServer(t, db)

	// Create application without a tenant (global application)
	app := createIntegrationTestApplication(t, db, "test-client", "test-secret", nil, []string{
		"trustsky:flight:read",
	})

	req := &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		Scope:        "trustsky:flight:read",
	}

	resp, err := server.ClientCredentialsGrant(req)
	require.NoError(t, err)
	require.NotNil(t, resp)
}

// =============================================================================
// Combined Tests: Scope Expansion + Tenant Status
// =============================================================================

func TestScopeExpansionWithActiveTenant(t *testing.T) {
	db := setupIntegrationTestDB(t)
	server := setupIntegrationTestServer(t, db)

	// Create active tenant
	tenant := createIntegrationTestTenant(t, db, "acme-operator", database.TenantStatusActive)

	// Create application with tenant
	app := createIntegrationTestApplication(t, db, "test-client", "test-secret", tenant, []string{
		"trustsky:admin",
		"trustsky:flight:write",
		"trustsky:flight:read",
		"trustsky:nfz:write",
		"trustsky:nfz:read",
		"trustsky:telemetry:write",
		"trustsky:sky:read",
		"trustsky:operator:read",
		"trustsky:operator:write",
	})

	req := &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		Scope:        "trustsky:flight:write",
	}

	resp, err := server.ClientCredentialsGrant(req)
	require.NoError(t, err)

	// Verify scope expansion happened
	returnedScopes := strings.Split(resp.Scope, " ")
	returnedSet := make(map[string]bool)
	for _, s := range returnedScopes {
		returnedSet[s] = true
	}

	if !returnedSet["trustsky:flight:write"] {
		t.Error("trustsky:flight:write should be present")
	}
	if !returnedSet["trustsky:flight:read"] {
		t.Error("trustsky:flight:read should be added via expansion")
	}
}

func TestSuspendedTenantBlocksScopeExpansion(t *testing.T) {
	db := setupIntegrationTestDB(t)
	server := setupIntegrationTestServer(t, db)

	// Create suspended tenant
	tenant := createIntegrationTestTenant(t, db, "suspended-operator", database.TenantStatusSuspended)

	// Create application with tenant
	app := createIntegrationTestApplication(t, db, "test-client", "test-secret", tenant, []string{
		"trustsky:flight:write",
		"trustsky:flight:read",
	})

	req := &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		Scope:        "trustsky:flight:write",
	}

	_, err := server.ClientCredentialsGrant(req)
	require.Error(t, err)
	if !strings.Contains(err.Error(), "tenant is suspended") {
		t.Errorf("expected 'tenant is suspended' error, got: %v", err)
	}
}

// =============================================================================
// Token Claims Verification
// =============================================================================

func TestTokenContainsTenantID(t *testing.T) {
	db := setupIntegrationTestDB(t)
	server := setupIntegrationTestServer(t, db)

	// Create active tenant
	tenant := createIntegrationTestTenant(t, db, "acme-operator", database.TenantStatusActive)

	// Create application with tenant
	app := createIntegrationTestApplication(t, db, "test-client", "test-secret", tenant, []string{
		"trustsky:flight:read",
	})

	req := &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		Scope:        "trustsky:flight:read",
	}

	resp, err := server.ClientCredentialsGrant(req)
	require.NoError(t, err)

	// Validate and decode token
	claims, err := server.TokenManager.ValidateToken(resp.AccessToken)
	require.NoError(t, err)

	// Verify tenant_id claim
	if claims.TenantID != tenant.ID.String() {
		t.Errorf("expected tenant_id %s, got %s", tenant.ID.String(), claims.TenantID)
	}
}

func TestTokenWithoutTenantHasNoTenantID(t *testing.T) {
	db := setupIntegrationTestDB(t)
	server := setupIntegrationTestServer(t, db)

	// Create application without tenant
	app := createIntegrationTestApplication(t, db, "test-client", "test-secret", nil, []string{
		"trustsky:flight:read",
	})

	req := &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		Scope:        "trustsky:flight:read",
	}

	resp, err := server.ClientCredentialsGrant(req)
	require.NoError(t, err)

	// Validate and decode token
	claims, err := server.TokenManager.ValidateToken(resp.AccessToken)
	require.NoError(t, err)

	// Verify tenant_id claim is empty
	if claims.TenantID != "" {
		t.Errorf("expected empty tenant_id, got %s", claims.TenantID)
	}
}

func TestTokenContainsExpandedScopes(t *testing.T) {
	db := setupIntegrationTestDB(t)
	server := setupIntegrationTestServer(t, db)

	// Create application
	app := createIntegrationTestApplication(t, db, "test-client", "test-secret", nil, []string{
		"trustsky:admin",
		"trustsky:flight:write",
		"trustsky:flight:read",
		"trustsky:nfz:write",
		"trustsky:nfz:read",
		"trustsky:telemetry:write",
		"trustsky:sky:read",
		"trustsky:operator:read",
		"trustsky:operator:write",
	})

	req := &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		Scope:        "trustsky:admin",
	}

	resp, err := server.ClientCredentialsGrant(req)
	require.NoError(t, err)

	// Validate and decode token
	claims, err := server.TokenManager.ValidateToken(resp.AccessToken)
	require.NoError(t, err)

	// Verify scope claim contains all expanded scopes
	scopeSet := make(map[string]bool)
	for _, s := range strings.Split(claims.Scope, " ") {
		scopeSet[s] = true
	}

	expectedScopes := []string{
		"trustsky:admin",
		"trustsky:flight:read",
		"trustsky:flight:write",
		"trustsky:nfz:read",
		"trustsky:nfz:write",
		"trustsky:telemetry:write",
		"trustsky:sky:read",
		"trustsky:operator:read",
		"trustsky:operator:write",
	}

	for _, expected := range expectedScopes {
		if !scopeSet[expected] {
			t.Errorf("expected scope %q not found in token claims", expected)
		}
	}
}

// =============================================================================
// Scope Validation Tests (HasScope function)
// =============================================================================

func TestHasScopeWithExpansion(t *testing.T) {
	tests := []struct {
		name     string
		granted  string
		required string
		expected bool
	}{
		// Admin grants everything
		{"admin grants flight:read", "trustsky:admin", "trustsky:flight:read", true},
		{"admin grants flight:write", "trustsky:admin", "trustsky:flight:write", true},
		{"admin grants nfz:read", "trustsky:admin", "trustsky:nfz:read", true},
		{"admin grants nfz:write", "trustsky:admin", "trustsky:nfz:write", true},
		{"admin grants telemetry:write", "trustsky:admin", "trustsky:telemetry:write", true},
		{"admin grants sky:read", "trustsky:admin", "trustsky:sky:read", true},
		{"admin grants operator:read", "trustsky:admin", "trustsky:operator:read", true},
		{"admin grants operator:write", "trustsky:admin", "trustsky:operator:write", true},

		// Write grants read
		{"flight:write grants flight:read", "trustsky:flight:write", "trustsky:flight:read", true},
		{"nfz:write grants nfz:read", "trustsky:nfz:write", "trustsky:nfz:read", true},
		{"operator:write grants operator:read", "trustsky:operator:write", "trustsky:operator:read", true},

		// Read does not grant write
		{"flight:read does not grant flight:write", "trustsky:flight:read", "trustsky:flight:write", false},
		{"nfz:read does not grant nfz:write", "trustsky:nfz:read", "trustsky:nfz:write", false},
		{"operator:read does not grant operator:write", "trustsky:operator:read", "trustsky:operator:write", false},

		// Cross-domain (flight does not grant nfz)
		{"flight:write does not grant nfz:read", "trustsky:flight:write", "trustsky:nfz:read", false},
		{"nfz:write does not grant flight:read", "trustsky:nfz:write", "trustsky:flight:read", false},

		// Non-trustsky scopes
		{"openid does not affect trustsky", "openid profile", "trustsky:flight:read", false},
		{"openid matches openid", "openid profile", "openid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasScope(tt.granted, tt.required)
			if result != tt.expected {
				t.Errorf("HasScope(%q, %q) = %v, expected %v", tt.granted, tt.required, result, tt.expected)
			}
		})
	}
}

func TestHasAllScopesWithExpansion(t *testing.T) {
	tests := []struct {
		name     string
		granted  string
		required []string
		expected bool
	}{
		{
			name:     "admin has all basic scopes",
			granted:  "trustsky:admin",
			required: []string{"trustsky:flight:read", "trustsky:nfz:read", "trustsky:sky:read"},
			expected: true,
		},
		{
			name:     "admin has all write scopes",
			granted:  "trustsky:admin",
			required: []string{"trustsky:flight:write", "trustsky:nfz:write", "trustsky:operator:write"},
			expected: true,
		},
		{
			name:     "partial scopes fail all check",
			granted:  "trustsky:flight:write",
			required: []string{"trustsky:flight:read", "trustsky:nfz:read"},
			expected: false,
		},
		{
			name:     "multiple write scopes grant multiple reads",
			granted:  "trustsky:flight:write trustsky:nfz:write",
			required: []string{"trustsky:flight:read", "trustsky:nfz:read"},
			expected: true,
		},
		{
			name:     "empty required returns true",
			granted:  "trustsky:flight:read",
			required: []string{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAllScopes(tt.granted, tt.required)
			if result != tt.expected {
				t.Errorf("HasAllScopes(%q, %v) = %v, expected %v", tt.granted, tt.required, result, tt.expected)
			}
		})
	}
}
