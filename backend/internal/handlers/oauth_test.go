package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tiiuae/oryxid/internal/config"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/oauth"
	"github.com/tiiuae/oryxid/internal/tokens"
	"github.com/tiiuae/oryxid/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestEnvironment(t *testing.T) (*gin.Engine, *gorm.DB, *tokens.TokenManager, *database.Application, *database.User) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	// Setup test database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Migrate models
	err = db.AutoMigrate(
		&database.User{},
		&database.Role{},
		&database.Permission{},
		&database.Application{},
		&database.Scope{},
		&database.Audience{},
		&database.AuthorizationCode{},
		&database.Token{},
		&database.Session{},
		&database.AuditLog{},
		&database.SigningKey{},
		&database.PushedAuthorizationRequest{},
	)
	require.NoError(t, err)

	// Generate test RSA keys
	privateKey, err := crypto.GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	jwtConfig := &config.JWTConfig{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		Kid:           "test-key-id",
		SigningMethod: jwt.SigningMethodRS256,
	}

	// Create token manager
	tm, err := tokens.NewTokenManager(jwtConfig, "http://localhost:8080")
	require.NoError(t, err)

	// Create OAuth server
	server := oauth.NewServer(db, tm)

	// Setup router
	router := gin.New()
	oauthHandler := NewOAuthHandler(server)

	// Register OAuth routes
	router.GET("/oauth/authorize", oauthHandler.AuthorizeHandler)
	router.POST("/oauth/token", oauthHandler.TokenHandler)
	router.POST("/oauth/introspect", oauthHandler.IntrospectHandler)
	router.POST("/oauth/revoke", oauthHandler.RevokeHandler)
	router.POST("/oauth/par", oauthHandler.PARHandler)
	router.GET("/oauth/userinfo", oauthHandler.UserInfoHandler)
	router.GET("/.well-known/jwks.json", oauthHandler.JWKSHandler)
	router.GET("/.well-known/openid-configuration", oauthHandler.DiscoveryHandler)

	// Create test application
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:                    "Test Application",
		ClientID:                "test-client-id",
		HashedClientSecret:      string(hashedSecret),
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              database.StringArray{"authorization_code", "refresh_token", "client_credentials"},
		ResponseTypes:           database.StringArray{"code"},
		RedirectURIs:            database.StringArray{"https://example.com/callback"},
	}
	require.NoError(t, db.Create(app).Error)

	// Create test user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user := &database.User{
		Username:      "testuser",
		Email:         "test@example.com",
		EmailVerified: true,
		Password:      string(hashedPassword),
		IsActive:      true,
		IsAdmin:       false,
	}
	require.NoError(t, db.Create(user).Error)

	return router, db, tm, app, user
}

func TestDiscoveryEndpoint(t *testing.T) {
	router, _, _, _, _ := setupTestEnvironment(t)

	req, _ := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var discovery map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &discovery)
	require.NoError(t, err)

	// Verify required fields
	assert.Equal(t, "http://localhost/.well-known/jwks.json", discovery["jwks_uri"])
	assert.Equal(t, "http://localhost/oauth/authorize", discovery["authorization_endpoint"])
	assert.Equal(t, "http://localhost/oauth/token", discovery["token_endpoint"])
	assert.Equal(t, "http://localhost/oauth/userinfo", discovery["userinfo_endpoint"])
	assert.Equal(t, "http://localhost/oauth/introspect", discovery["introspection_endpoint"])
	assert.Equal(t, "http://localhost/oauth/revoke", discovery["revocation_endpoint"])
	assert.Equal(t, "http://localhost/oauth/par", discovery["pushed_authorization_request_endpoint"])

	// Verify supported features
	assert.Contains(t, discovery["response_types_supported"], "code")
	assert.Contains(t, discovery["grant_types_supported"], "authorization_code")
	assert.Contains(t, discovery["code_challenge_methods_supported"], "S256")
}

func TestJWKSEndpoint(t *testing.T) {
	router, _, _, _, _ := setupTestEnvironment(t)

	req, _ := http.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var jwks map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &jwks)
	require.NoError(t, err)

	keys, ok := jwks["keys"].([]interface{})
	assert.True(t, ok)
	assert.Greater(t, len(keys), 0, "JWKS should contain at least one key")

	// Verify key structure
	if len(keys) > 0 {
		key := keys[0].(map[string]interface{})
		assert.Equal(t, "RSA", key["kty"])
		assert.NotEmpty(t, key["kid"])
		assert.NotEmpty(t, key["n"])
		assert.NotEmpty(t, key["e"])
	}
}

func TestTokenEndpoint_ClientCredentials(t *testing.T) {
	router, _, _, app, _ := setupTestEnvironment(t)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "openid profile")

	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response["access_token"])
	assert.Equal(t, "Bearer", response["token_type"])
	assert.NotNil(t, response["expires_in"])
}

func TestTokenEndpoint_InvalidClient(t *testing.T) {
	router, _, _, _, _ := setupTestEnvironment(t)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("invalid-client", "invalid-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "invalid_client", response["error"])
}

func TestPAREndpoint(t *testing.T) {
	router, _, _, app, _ := setupTestEnvironment(t)

	data := url.Values{}
	data.Set("response_type", "code")
	data.Set("redirect_uri", "https://example.com/callback")
	data.Set("scope", "openid profile")
	data.Set("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	data.Set("code_challenge_method", "S256")
	data.Set("state", "test-state")

	req, _ := http.NewRequest("POST", "/oauth/par", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response["request_uri"])
	assert.Equal(t, float64(90), response["expires_in"])
	assert.Contains(t, response["request_uri"], "urn:ietf:params:oauth:request_uri:")
}

func TestIntrospectionEndpoint(t *testing.T) {
	router, _, tm, app, user := setupTestEnvironment(t)

	// Generate a test token
	accessToken, err := tm.GenerateAccessToken(app, user, "openid profile", "", nil)
	require.NoError(t, err)

	data := url.Values{}
	data.Set("token", accessToken)

	req, _ := http.NewRequest("POST", "/oauth/introspect", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, true, response["active"])
	assert.Equal(t, app.ClientID, response["client_id"])
	assert.Contains(t, response["scope"], "openid")
}

func TestIntrospectionEndpoint_InvalidToken(t *testing.T) {
	router, _, _, app, _ := setupTestEnvironment(t)

	data := url.Values{}
	data.Set("token", "invalid-token")

	req, _ := http.NewRequest("POST", "/oauth/introspect", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, false, response["active"])
}

func TestRevocationEndpoint(t *testing.T) {
	router, _, tm, app, user := setupTestEnvironment(t)

	// Generate a test refresh token
	refreshToken, err := tm.GenerateRefreshToken(app, user, "openid profile")
	require.NoError(t, err)

	data := url.Values{}
	data.Set("token", refreshToken)
	data.Set("token_type_hint", "refresh_token")

	req, _ := http.NewRequest("POST", "/oauth/revoke", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestUserInfoEndpoint(t *testing.T) {
	router, _, tm, app, user := setupTestEnvironment(t)

	// Generate a test token with openid scope
	accessToken, err := tm.GenerateAccessToken(app, user, "openid profile email", "", nil)
	require.NoError(t, err)

	req, _ := http.NewRequest("GET", "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response["sub"])
	assert.Equal(t, user.Username, response["username"])
	assert.Equal(t, user.Email, response["email"])
	assert.Equal(t, true, response["email_verified"])
}

func TestUserInfoEndpoint_MissingOpenIDScope(t *testing.T) {
	router, _, tm, app, user := setupTestEnvironment(t)

	// Generate a test token WITHOUT openid scope
	accessToken, err := tm.GenerateAccessToken(app, user, "profile", "", nil)
	require.NoError(t, err)

	req, _ := http.NewRequest("GET", "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "insufficient_scope", response["error"])
}

func TestUserInfoEndpoint_NoToken(t *testing.T) {
	router, _, _, _, _ := setupTestEnvironment(t)

	req, _ := http.NewRequest("GET", "/oauth/userinfo", nil)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestPKCEValidation(t *testing.T) {
	router, db, _, app, user := setupTestEnvironment(t)

	// Create authorization code with PKCE
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	authCode := &database.AuthorizationCode{
		Code:                "test-code",
		ApplicationID:       app.ID,
		UserID:              &user.ID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}
	require.NoError(t, db.Create(authCode).Error)

	// Test valid PKCE flow
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", "test-code")
	data.Set("redirect_uri", "https://example.com/callback")
	data.Set("code_verifier", codeVerifier)

	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.NotEmpty(t, response["access_token"])
	assert.NotEmpty(t, response["refresh_token"])
	assert.NotEmpty(t, response["id_token"])
}

func TestPKCEValidation_WrongVerifier(t *testing.T) {
	router, db, _, app, user := setupTestEnvironment(t)

	// Create authorization code with PKCE
	codeChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	authCode := &database.AuthorizationCode{
		Code:                "test-code-wrong",
		ApplicationID:       app.ID,
		UserID:              &user.ID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}
	require.NoError(t, db.Create(authCode).Error)

	// Test with wrong verifier
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", "test-code-wrong")
	data.Set("redirect_uri", "https://example.com/callback")
	data.Set("code_verifier", "wrong-verifier")

	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTokenEndpoint_MissingGrantType(t *testing.T) {
	router, _, _, app, _ := setupTestEnvironment(t)

	data := url.Values{}
	// No grant_type

	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "unsupported_grant_type", response["error"])
}

func TestTokenEndpoint_UnsupportedGrantType(t *testing.T) {
	router, _, _, app, _ := setupTestEnvironment(t)

	data := url.Values{}
	data.Set("grant_type", "implicit") // Unsupported per OAuth 2.1

	req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(app.ClientID, "test-secret")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "unsupported_grant_type", response["error"])
}

// Benchmark tests
func BenchmarkTokenEndpoint_ClientCredentials(b *testing.B) {
	router, _, _, app, _ := setupTestEnvironment(&testing.T{})

	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "/oauth/token", strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(app.ClientID, "test-secret")

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkDiscoveryEndpoint(b *testing.B) {
	router, _, _, _, _ := setupTestEnvironment(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
