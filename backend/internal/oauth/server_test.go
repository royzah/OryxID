package oauth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tiiuae/oryxid/internal/config"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/tokens"
	"github.com/tiiuae/oryxid/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Migrate models (excluding those that reference Application due to pq.StringArray compatibility issues with SQLite)
	// AuthorizationCode, Token, Scope, and Audience all have relationships with Application
	err = db.AutoMigrate(
		&database.User{},
		&database.Role{},
		&database.Permission{},
		&database.Session{},
		&database.SigningKey{},
		&database.PushedAuthorizationRequest{},
	)
	require.NoError(t, err)

	// Manually create Application table (SQLite doesn't support TEXT[] arrays, use TEXT for JSON storage)
	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS applications (
			id TEXT PRIMARY KEY,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME,
			name TEXT NOT NULL,
			description TEXT,
			client_id TEXT UNIQUE NOT NULL,
			hashed_client_secret TEXT NOT NULL,
			client_type TEXT NOT NULL,
			token_endpoint_auth_method TEXT,
			public_key_pem TEXT,
			jwks_uri TEXT,
			grant_types TEXT,
			response_types TEXT,
			redirect_uris TEXT,
			post_logout_uris TEXT,
			skip_authorization BOOLEAN DEFAULT 0,
			access_token_lifespan INTEGER,
			refresh_token_lifespan INTEGER,
			owner_id TEXT,
			metadata TEXT
		)
	`).Error
	require.NoError(t, err)

	// Manually create Scope table
	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS scopes (
			id TEXT PRIMARY KEY,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			is_default BOOLEAN DEFAULT 0
		)
	`).Error
	require.NoError(t, err)

	// Manually create Audience table
	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS audiences (
			id TEXT PRIMARY KEY,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME,
			identifier TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			description TEXT
		)
	`).Error
	require.NoError(t, err)

	// Create many-to-many join tables
	err = db.Exec(`CREATE TABLE IF NOT EXISTS application_scopes (application_id TEXT, scope_id TEXT, PRIMARY KEY (application_id, scope_id))`).Error
	require.NoError(t, err)

	err = db.Exec(`CREATE TABLE IF NOT EXISTS audience_scopes (audience_id TEXT, scope_id TEXT, PRIMARY KEY (audience_id, scope_id))`).Error
	require.NoError(t, err)

	err = db.Exec(`CREATE TABLE IF NOT EXISTS application_audiences (application_id TEXT, audience_id TEXT, PRIMARY KEY (application_id, audience_id))`).Error
	require.NoError(t, err)

	// Manually create AuthorizationCode table
	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS authorization_codes (
			id TEXT PRIMARY KEY,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME,
			code TEXT UNIQUE NOT NULL,
			application_id TEXT NOT NULL,
			user_id TEXT,
			redirect_uri TEXT,
			scope TEXT,
			audience TEXT,
			state TEXT,
			nonce TEXT,
			code_challenge TEXT,
			code_challenge_method TEXT,
			expires_at DATETIME,
			used BOOLEAN DEFAULT 0
		)
	`).Error
	require.NoError(t, err)

	// Manually create Token table
	err = db.Exec(`
		CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			created_at DATETIME,
			updated_at DATETIME,
			deleted_at DATETIME,
			token_hash TEXT UNIQUE NOT NULL,
			token_type TEXT NOT NULL,
			application_id TEXT NOT NULL,
			user_id TEXT,
			scope TEXT,
			audience TEXT,
			expires_at DATETIME,
			revoked BOOLEAN DEFAULT 0,
			revoked_at DATETIME
		)
	`).Error
	require.NoError(t, err)

	return db
}

func createTestTokenManager(t *testing.T) *tokens.TokenManager {
	// Generate test RSA key pair in memory (faster than file I/O)
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

	return tm
}

func createTestApplication(t *testing.T, db *gorm.DB) *database.Application {
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	require.NoError(t, err)

	app := &database.Application{
		Name:                    "Test Application",
		ClientID:                "test-client-id",
		HashedClientSecret:      string(hashedSecret),
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              pq.StringArray{"authorization_code", "refresh_token", "client_credentials"},
		ResponseTypes:           pq.StringArray{"code"},
		RedirectURIs:            pq.StringArray{"https://example.com/callback"},
	}

	// Use Table() to explicitly specify table name and bypass some GORM model introspection
	err = db.Table("applications").Create(app).Error
	require.NoError(t, err)

	return app
}

func createTestUser(t *testing.T, db *gorm.DB) *database.User {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := &database.User{
		Username:      "testuser",
		Email:         "test@example.com",
		EmailVerified: true,
		Password:      string(hashedPassword),
		IsActive:      true,
		IsAdmin:       false,
	}

	err = db.Create(user).Error
	require.NoError(t, err)

	return user
}

func TestValidatePKCE(t *testing.T) {
	tests := []struct {
		name      string
		challenge string
		method    string
		verifier  string
		expected  bool
	}{
		{
			name:      "Valid S256",
			challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			method:    "S256",
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			expected:  true,
		},
		{
			name:      "Invalid S256 - wrong verifier",
			challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			method:    "S256",
			verifier:  "wrong-verifier",
			expected:  false,
		},
		{
			name:      "Plain method rejected (OAuth 2.1)",
			challenge: "test-challenge",
			method:    "plain",
			verifier:  "test-challenge",
			expected:  false,
		},
		{
			name:      "Invalid method",
			challenge: "test",
			method:    "invalid",
			verifier:  "test",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validatePKCE(tt.challenge, tt.method, tt.verifier)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateAuthorizationCode(t *testing.T) {
	db := setupTestDB(t)
	app := createTestApplication(t, db)
	user := createTestUser(t, db)

	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	req := &AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            app.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile email",
		State:               "random-state",
		Nonce:               "random-nonce",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}

	code, err := server.GenerateAuthorizationCode(app, user, req)
	require.NoError(t, err)
	assert.NotEmpty(t, code)
	assert.Greater(t, len(code), 32) // Ensure code is long enough

	// Verify code is stored in database
	var authCode database.AuthorizationCode
	err = db.Where("code = ?", code).First(&authCode).Error
	require.NoError(t, err)
	assert.Equal(t, app.ID, authCode.ApplicationID)
	assert.Equal(t, user.ID, *authCode.UserID)
	assert.Equal(t, req.Scope, authCode.Scope)
	assert.Equal(t, req.Nonce, authCode.Nonce)
	assert.Equal(t, req.CodeChallenge, authCode.CodeChallenge)
	assert.Equal(t, req.CodeChallengeMethod, authCode.CodeChallengeMethod)
}

func TestScopeDownscaling(t *testing.T) {
	db := setupTestDB(t)
	app := createTestApplication(t, db)
	user := createTestUser(t, db)

	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	originalScope := "openid profile email offline_access"

	t.Run("Downscale to subset of scopes", func(t *testing.T) {
		// Generate fresh refresh token for this test
		refreshToken, err := tm.GenerateRefreshToken(app, user, originalScope)
		require.NoError(t, err)

		// Store the refresh token
		server.storeTokens(app, user, "", refreshToken)

		req := &TokenRequest{
			GrantType:    "refresh_token",
			ClientID:     app.ClientID,
			ClientSecret: "test-secret",
			RefreshToken: refreshToken,
			Scope:        "openid profile", // Requesting fewer scopes
		}

		response, err := server.RefreshTokenGrant(req)
		require.NoError(t, err)
		assert.Equal(t, "openid profile", response.Scope)
	})

	t.Run("Reject scope escalation", func(t *testing.T) {
		// Generate fresh refresh token for this test
		refreshToken, err := tm.GenerateRefreshToken(app, user, originalScope)
		require.NoError(t, err)

		// Store the refresh token
		server.storeTokens(app, user, "", refreshToken)

		req := &TokenRequest{
			GrantType:    "refresh_token",
			ClientID:     app.ClientID,
			ClientSecret: "test-secret",
			RefreshToken: refreshToken,
			Scope:        "openid profile email admin", // Trying to add 'admin' scope
		}

		_, err = server.RefreshTokenGrant(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds granted scope")
	})
}

func TestRefreshTokenRotation(t *testing.T) {
	db := setupTestDB(t)
	app := createTestApplication(t, db)
	user := createTestUser(t, db)

	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Generate initial refresh token
	refreshToken1, err := tm.GenerateRefreshToken(app, user, "openid profile")
	require.NoError(t, err)

	server.storeTokens(app, user, "", refreshToken1)

	// Use refresh token to get new tokens
	req := &TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		RefreshToken: refreshToken1,
	}

	response, err := server.RefreshTokenGrant(req)
	require.NoError(t, err)

	// Verify we got a new refresh token
	assert.NotEmpty(t, response.RefreshToken)
	assert.NotEqual(t, refreshToken1, response.RefreshToken)

	// Verify old refresh token is revoked
	var revokedToken database.Token
	err = db.Where("token_type = ? AND revoked = ?", "refresh", true).First(&revokedToken).Error
	require.NoError(t, err)

	// Try to use old refresh token again - should fail
	req2 := &TokenRequest{
		GrantType:    "refresh_token",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		RefreshToken: refreshToken1,
	}

	_, err = server.RefreshTokenGrant(req2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "revoked")
}

func TestPARCreationAndValidation(t *testing.T) {
	db := setupTestDB(t)
	app := createTestApplication(t, db)

	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	req := &AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            app.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		State:               "test-state",
		Nonce:               "test-nonce",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}

	// Create PAR
	parResponse, err := server.CreatePushedAuthorizationRequest(req, "test-secret")
	require.NoError(t, err)
	assert.NotEmpty(t, parResponse.RequestURI)
	assert.Equal(t, 90, parResponse.ExpiresIn)
	assert.Contains(t, parResponse.RequestURI, "urn:ietf:params:oauth:request_uri:")

	// Validate PAR
	par, err := server.ValidatePAR(parResponse.RequestURI, app.ClientID)
	require.NoError(t, err)
	assert.Equal(t, req.Scope, par.Scope)
	assert.Equal(t, req.Nonce, par.Nonce)
	assert.Equal(t, req.CodeChallenge, par.CodeChallenge)

	// Try to use PAR again (one-time use)
	_, err = server.ValidatePAR(parResponse.RequestURI, app.ClientID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already used")
}

func TestPARExpiration(t *testing.T) {
	db := setupTestDB(t)
	app := createTestApplication(t, db)

	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Create PAR
	parRequest := &database.PushedAuthorizationRequest{
		RequestURI:          "urn:ietf:params:oauth:request_uri:test-expired",
		ApplicationID:       app.ID,
		ResponseType:        "code",
		ClientID:            app.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		ExpiresAt:           time.Now().Add(-1 * time.Minute), // Already expired
		Used:                false,
	}

	err := db.Create(parRequest).Error
	require.NoError(t, err)

	// Try to validate expired PAR
	_, err = server.ValidatePAR(parRequest.RequestURI, app.ClientID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestClientIDMismatchInPAR(t *testing.T) {
	db := setupTestDB(t)
	app := createTestApplication(t, db)

	// Create PAR for one client
	parRequest := &database.PushedAuthorizationRequest{
		RequestURI:    "urn:ietf:params:oauth:request_uri:test-mismatch",
		ApplicationID: app.ID,
		ResponseType:  "code",
		ClientID:      app.ClientID,
		RedirectURI:   "https://example.com/callback",
		Scope:         "openid",
		ExpiresAt:     time.Now().Add(90 * time.Second),
		Used:          false,
	}

	err := db.Create(parRequest).Error
	require.NoError(t, err)

	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Try to use PAR with different client_id
	_, err = server.ValidatePAR(parRequest.RequestURI, "different-client-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mismatch")
}
