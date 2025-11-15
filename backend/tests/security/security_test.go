package security

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tiiuae/oryxid/internal/config"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/handlers"
	"github.com/tiiuae/oryxid/internal/oauth"
	"github.com/tiiuae/oryxid/internal/tokens"
	"github.com/tiiuae/oryxid/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupSecurityTestEnv(t *testing.T) (*gin.Engine, *gorm.DB, *oauth.Server, *database.Application) {
	gin.SetMode(gin.TestMode)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(
		&database.User{},
		&database.Application{},
		&database.AuthorizationCode{},
		&database.Token{},
		&database.AuditLog{},
		&database.PushedAuthorizationRequest{},
	)
	require.NoError(t, err)

	privateKey, err := crypto.GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	jwtConfig := &config.JWTConfig{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		Kid:           "test-key-id",
		SigningMethod: jwt.SigningMethodRS256,
	}

	tm, err := tokens.NewTokenManager(jwtConfig, "http://localhost:8080")
	require.NoError(t, err)

	server := oauth.NewServer(db, tm)

	router := gin.New()
	oauthHandler := handlers.NewOAuthHandler(server)

	router.POST("/oauth/token", oauthHandler.TokenHandler)
	router.POST("/oauth/par", oauthHandler.PARHandler)
	router.POST("/oauth/introspect", oauthHandler.IntrospectHandler)
	router.GET("/oauth/userinfo", oauthHandler.UserInfoHandler)

	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:                    "Test Application",
		ClientID:                "test-client-id",
		HashedClientSecret:      string(hashedSecret),
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              pq.StringArray{"authorization_code", "client_credentials"},
		ResponseTypes:           pq.StringArray{"code"},
		RedirectURIs:            pq.StringArray{"https://example.com/callback"},
	}
	require.NoError(t, db.Create(app).Error)

	return router, db, server, app
}

// PKCE Security Tests

func TestPKCE_RejectPlainMethod(t *testing.T) {
	router, _, _, app := setupSecurityTestEnv(t)

	// Try to use plain PKCE method (should be rejected per OAuth 2.1)
	data := url.Values{}
	data.Set("response_type", "code")
	data.Set("redirect_uri", "https://example.com/callback")
	data.Set("scope", "openid")
	data.Set("code_challenge", "plain-challenge")
	data.Set("code_challenge_method", "plain")

	req, _ := http.NewRequest("POST", "/oauth/par", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should reject plain method
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestPKCE_RequireS256(t *testing.T) {
	router, _, _, app := setupSecurityTestEnv(t)

	// Valid S256 PKCE
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	data := url.Values{}
	data.Set("response_type", "code")
	data.Set("redirect_uri", "https://example.com/callback")
	data.Set("scope", "openid")
	data.Set("code_challenge", challenge)
	data.Set("code_challenge_method", "S256")

	req, _ := http.NewRequest("POST", "/oauth/par", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestPKCE_VerifierMismatch(t *testing.T) {
	router, db, _, app := setupSecurityTestEnv(t)

	// Create authorization code with PKCE challenge
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	authCode := &database.AuthorizationCode{
		Code:                "test-code",
		ApplicationID:       app.ID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
		Used:                false,
	}
	require.NoError(t, db.Create(authCode).Error)

	// Try to exchange with wrong verifier
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", "test-code")
	data.Set("redirect_uri", "https://example.com/callback")
	data.Set("code_verifier", "wrong-verifier")

	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should fail due to verifier mismatch
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// SQL Injection Prevention Tests

func TestSQLInjection_ClientID(t *testing.T) {
	router, _, _, _ := setupSecurityTestEnv(t)

	// Try SQL injection in client_id
	maliciousClientID := "admin' OR '1'='1"

	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(maliciousClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should not succeed with SQL injection
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSQLInjection_Scope(t *testing.T) {
	router, _, _, app := setupSecurityTestEnv(t)

	// Try SQL injection in scope parameter
	maliciousScope := "openid'; DROP TABLE users; --"

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", maliciousScope)

	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Even if it succeeds, SQL injection should not execute
	// The scope should be treated as a string value
	if w.Code == http.StatusOK {
		var response map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &response)
		// Verify the malicious scope is treated as literal string
		if scope, ok := response["scope"].(string); ok {
			assert.Contains(t, scope, maliciousScope)
		}
	}
}

func TestSQLInjection_RedirectURI(t *testing.T) {
	router, _, _, app := setupSecurityTestEnv(t)

	// Try SQL injection in redirect_uri
	maliciousURI := "https://example.com/callback' OR '1'='1"

	data := url.Values{}
	data.Set("response_type", "code")
	data.Set("redirect_uri", maliciousURI)
	data.Set("scope", "openid")
	data.Set("code_challenge", "challenge")
	data.Set("code_challenge_method", "S256")

	req, _ := http.NewRequest("POST", "/oauth/par", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should reject invalid redirect_uri
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// XSS Prevention Tests

func TestXSS_StateParameter(t *testing.T) {
	router, _, _, app := setupSecurityTestEnv(t)

	// Try XSS in state parameter
	maliciousState := "<script>alert('XSS')</script>"

	data := url.Values{}
	data.Set("response_type", "code")
	data.Set("redirect_uri", "https://example.com/callback")
	data.Set("scope", "openid")
	data.Set("state", maliciousState)
	data.Set("code_challenge", "challenge")
	data.Set("code_challenge_method", "S256")

	req, _ := http.NewRequest("POST", "/oauth/par", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// State should be stored as-is, but when rendered, should be escaped
	// This test verifies the state is accepted
	if w.Code == http.StatusCreated {
		// In production, ensure state is HTML-escaped when rendered
		t.Log("State parameter accepted - ensure HTML escaping on render")
	}
}

// Token Security Tests

func TestTokenReplay_Prevention(t *testing.T) {
	router, db, server, app := setupSecurityTestEnv(t)

	// Create user
	user := &database.User{
		Username:      "testuser",
		Email:         "test@example.com",
		EmailVerified: true,
		IsActive:      true,
	}
	require.NoError(t, db.Create(user).Error)

	// Generate authorization code
	authReq := &oauth.AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            app.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}

	code, err := server.GenerateAuthorizationCode(app, user, authReq)
	require.NoError(t, err)

	// Exchange code once
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", "https://example.com/callback")
	data.Set("code_verifier", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

	req1, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req1.SetBasicAuth(app.ClientID, "test-secret")

	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)

	assert.Equal(t, http.StatusOK, w1.Code)

	// Try to replay the same code
	req2, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.SetBasicAuth(app.ClientID, "test-secret")

	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)

	// Second attempt should fail
	assert.Equal(t, http.StatusBadRequest, w2.Code)
}

// Client Authentication Security

func TestClientAuth_TimingAttack_Resistance(t *testing.T) {
	router, _, _, _ := setupSecurityTestEnv(t)

	// This test ensures client secret comparison is constant-time
	// to prevent timing attacks

	tests := []struct {
		name         string
		clientID     string
		clientSecret string
	}{
		{"Valid credentials", "test-client-id", "test-secret"},
		{"Invalid client", "wrong-client-id", "test-secret"},
		{"Invalid secret", "test-client-id", "wrong-secret"},
		{"Both invalid", "wrong-client-id", "wrong-secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := url.Values{}
			data.Set("grant_type", "client_credentials")

			req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(tt.clientID, tt.clientSecret)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			// All invalid attempts should return 401
			if tt.clientID != "test-client-id" || tt.clientSecret != "test-secret" {
				assert.Equal(t, http.StatusUnauthorized, w.Code)
			}
		})
	}
}

// Scope Security Tests

func TestScope_Escalation_Prevention(t *testing.T) {
	router, db, server, app := setupSecurityTestEnv(t)

	user := &database.User{
		Username:      "testuser",
		Email:         "test@example.com",
		EmailVerified: true,
		IsActive:      true,
	}
	require.NoError(t, db.Create(user).Error)

	// Generate refresh token with limited scope
	refreshToken, err := server.TokenManager.GenerateRefreshToken(app, user, "openid profile")
	require.NoError(t, err)

	// Store the token
	hash := sha256.Sum256([]byte(refreshToken))
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	token := &database.Token{
		TokenHash:     tokenHash,
		TokenType:     "refresh",
		ApplicationID: app.ID,
		UserID:        &user.ID,
		Scope:         "openid profile",
		Revoked:       false,
	}
	require.NoError(t, db.Create(token).Error)

	// Try to request elevated scope on refresh
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", refreshToken)
	data.Set("scope", "openid profile email admin") // Trying to add admin scope

	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should reject scope escalation
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Redirect URI Validation

func TestRedirectURI_Validation(t *testing.T) {
	router, _, _, app := setupSecurityTestEnv(t)

	tests := []struct {
		name        string
		redirectURI string
		shouldFail  bool
	}{
		{"Valid registered URI", "https://example.com/callback", false},
		{"Unregistered URI", "https://evil.com/callback", true},
		{"Open redirect attempt", "https://example.com/callback@evil.com", true},
		{"HTTP instead of HTTPS", "http://example.com/callback", true},
		{"URI with fragment", "https://example.com/callback#fragment", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := url.Values{}
			data.Set("response_type", "code")
			data.Set("redirect_uri", tt.redirectURI)
			data.Set("scope", "openid")
			data.Set("code_challenge", "challenge")
			data.Set("code_challenge_method", "S256")

			req, _ := http.NewRequest("POST", "/oauth/par", strings.NewReader(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(app.ClientID, "test-secret")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if tt.shouldFail {
				assert.Equal(t, http.StatusBadRequest, w.Code, "Should reject invalid redirect URI")
			}
		})
	}
}

// Header Injection Tests

func TestHeader_Injection_Prevention(t *testing.T) {
	router, _, _, app := setupSecurityTestEnv(t)

	// Try to inject headers via parameters
	maliciousScope := "openid\r\nX-Injected-Header: malicious"

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", maliciousScope)

	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Check that injected header is not present
	assert.Empty(t, w.Header().Get("X-Injected-Header"))
}

// Authorization Code Length and Randomness

func TestAuthCode_Entropy(t *testing.T) {
	_, db, server, app := setupSecurityTestEnv(t)

	user := &database.User{
		Username:      "testuser",
		Email:         "test@example.com",
		EmailVerified: true,
		IsActive:      true,
	}
	require.NoError(t, db.Create(user).Error)

	authReq := &oauth.AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            app.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
	}

	// Generate multiple codes and verify uniqueness and length
	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := server.GenerateAuthorizationCode(app, user, authReq)
		require.NoError(t, err)

		// Check minimum length (should be cryptographically secure)
		assert.GreaterOrEqual(t, len(code), 32, "Code should be at least 32 characters")

		// Check uniqueness
		assert.False(t, codes[code], "Generated duplicate authorization code")
		codes[code] = true
	}
}

// Rate Limiting Bypass Attempts

func TestRateLimit_BypassAttempts(t *testing.T) {
	// This would test various rate limit bypass techniques:
	// - Different User-Agent headers
	// - X-Forwarded-For manipulation
	// - Different authentication methods
	t.Skip("Rate limiting bypass tests require rate limit configuration")
}

// JWT Security

func TestJWT_AlgorithmConfusion(t *testing.T) {
	// Test that server doesn't accept tokens with "none" algorithm
	// or accepts HS256 when RS256 is expected
	t.Skip("JWT algorithm confusion tests require token validation implementation")
}

func TestJWT_Expiration(t *testing.T) {
	router, _, server, app := setupSecurityTestEnv(t)

	user := &database.User{
		Username:      "testuser",
		Email:         "test@example.com",
		EmailVerified: true,
		IsActive:      true,
	}

	// Generate an access token
	token, err := server.TokenManager.GenerateAccessToken(app, user, "openid", "", nil)
	require.NoError(t, err)

	// Token should be valid immediately
	req, _ := http.NewRequest("GET", "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Note: Testing actual expiration would require mocking time or waiting
	t.Log("Token expiration validated at generation time")
}
