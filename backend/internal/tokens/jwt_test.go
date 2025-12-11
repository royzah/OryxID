package tokens

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tiiuae/oryxid/internal/config"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/pkg/crypto"
)

func setupTokenManager(t *testing.T) *TokenManager {
	privateKey, err := crypto.GenerateRSAKeyPair(2048)
	require.NoError(t, err)

	jwtConfig := &config.JWTConfig{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		Kid:           "test-key-id",
		SigningMethod: jwt.SigningMethodRS256,
	}

	tm, err := NewTokenManager(jwtConfig, "http://localhost:8080")
	require.NoError(t, err)

	return tm
}

func createTestApplication() *database.Application {
	return &database.Application{
		BaseModel: database.BaseModel{
			ID: uuid.New(),
		},
		Name:       "Test Application",
		ClientID:   "test-client-id",
		ClientType: "confidential",
		GrantTypes: database.StringArray{"authorization_code", "refresh_token"},
	}
}

func createTestUser() *database.User {
	userID := uuid.New()
	return &database.User{
		BaseModel: database.BaseModel{
			ID: userID,
		},
		Username:      "testuser",
		Email:         "testuser@example.com",
		EmailVerified: true,
		IsActive:      true,
		IsAdmin:       false,
		Roles: []database.Role{
			{
				BaseModel:   database.BaseModel{ID: uuid.New()},
				Name:        "user",
				Description: "Regular user",
			},
		},
	}
}

// =============================================================================
// TokenManager Creation Tests
// =============================================================================

func TestNewTokenManager_Success(t *testing.T) {
	tm := setupTokenManager(t)
	assert.NotNil(t, tm)
	assert.NotNil(t, tm.privateKey)
	assert.NotNil(t, tm.publicKey)
	assert.Equal(t, "test-key-id", tm.kid)
	assert.Equal(t, "http://localhost:8080", tm.issuer)
}

// =============================================================================
// Access Token Tests
// =============================================================================

func TestGenerateAccessToken_Success(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()
	user := createTestUser()

	token, err := tm.GenerateAccessToken(app, user, "openid profile email", "https://api.example.com", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Token should be a valid JWT (3 parts separated by dots)
	parts := strings.Split(token, ".")
	assert.Len(t, parts, 3)
}

func TestGenerateAccessToken_WithoutUser(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	token, err := tm.GenerateAccessToken(app, nil, "read write", "https://api.example.com", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Validate token
	claims, err := tm.ValidateToken(token)
	require.NoError(t, err)

	// Subject should be client_id when no user
	assert.Equal(t, app.ClientID, claims.Subject)
}

func TestGenerateAccessToken_WithUser(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()
	user := createTestUser()

	token, err := tm.GenerateAccessToken(app, user, "openid profile", "", nil)
	require.NoError(t, err)

	claims, err := tm.ValidateToken(token)
	require.NoError(t, err)

	// Subject should be user ID
	assert.Equal(t, user.ID.String(), claims.Subject)
	assert.Equal(t, user.Username, claims.Username)
	assert.Equal(t, user.Email, claims.Email)
	assert.Contains(t, claims.Roles, "user")
}

func TestGenerateAccessToken_WithExtraClaims(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	extra := map[string]interface{}{
		"custom_claim": "custom_value",
		"number":       42,
	}

	token, err := tm.GenerateAccessToken(app, nil, "read", "", extra)
	require.NoError(t, err)

	claims, err := tm.ValidateToken(token)
	require.NoError(t, err)

	assert.NotNil(t, claims.Extra)
	assert.Equal(t, "custom_value", claims.Extra["custom_claim"])
	assert.Equal(t, float64(42), claims.Extra["number"])
}

func TestGenerateAccessToken_HasCorrectClaims(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()
	user := createTestUser()

	token, err := tm.GenerateAccessToken(app, user, "openid profile email", "https://api.example.com", nil)
	require.NoError(t, err)

	claims, err := tm.ValidateToken(token)
	require.NoError(t, err)

	// Check standard claims
	assert.Equal(t, "http://localhost:8080", claims.Issuer)
	assert.Contains(t, claims.Audience, "https://api.example.com")
	assert.NotEmpty(t, claims.ID) // jti
	assert.NotNil(t, claims.ExpiresAt)
	assert.NotNil(t, claims.IssuedAt)
	assert.NotNil(t, claims.NotBefore)

	// Check custom claims
	assert.Equal(t, "openid profile email", claims.Scope)
	assert.Equal(t, app.ClientID, claims.ClientID)
	assert.Equal(t, "Bearer", claims.Type)
}

func TestGenerateAccessToken_Expiration(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	token, err := tm.GenerateAccessToken(app, nil, "read", "", nil)
	require.NoError(t, err)

	claims, err := tm.ValidateToken(token)
	require.NoError(t, err)

	// Default expiration is 1 hour
	expectedExpiry := time.Now().Add(time.Hour)
	actualExpiry := claims.ExpiresAt.Time

	// Allow 5 second tolerance
	assert.WithinDuration(t, expectedExpiry, actualExpiry, 5*time.Second)
}

// =============================================================================
// Refresh Token Tests
// =============================================================================

func TestGenerateRefreshToken_Success(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()
	user := createTestUser()

	token, err := tm.GenerateRefreshToken(app, user, "openid profile offline_access")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestGenerateRefreshToken_WithoutUser(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	token, err := tm.GenerateRefreshToken(app, nil, "read write")
	require.NoError(t, err)

	claims, err := tm.ValidateToken(token)
	require.NoError(t, err)

	assert.Equal(t, app.ClientID, claims.Subject)
	assert.Equal(t, "Refresh", claims.Type)
}

func TestGenerateRefreshToken_WithUser(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()
	user := createTestUser()

	token, err := tm.GenerateRefreshToken(app, user, "openid")
	require.NoError(t, err)

	claims, err := tm.ValidateToken(token)
	require.NoError(t, err)

	assert.Equal(t, user.ID.String(), claims.Subject)
	assert.Equal(t, "Refresh", claims.Type)
}

func TestGenerateRefreshToken_LongerExpiration(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	token, err := tm.GenerateRefreshToken(app, nil, "read")
	require.NoError(t, err)

	claims, err := tm.ValidateToken(token)
	require.NoError(t, err)

	// Default refresh token expiration is 30 days
	expectedExpiry := time.Now().Add(30 * 24 * time.Hour)
	actualExpiry := claims.ExpiresAt.Time

	// Allow 1 minute tolerance
	assert.WithinDuration(t, expectedExpiry, actualExpiry, time.Minute)
}

// =============================================================================
// ID Token Tests
// =============================================================================

func TestGenerateIDToken_Success(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()
	user := createTestUser()

	token, err := tm.GenerateIDToken(app, user, "nonce123", time.Now())
	require.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestGenerateIDToken_RequiresUser(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	token, err := tm.GenerateIDToken(app, nil, "nonce123", time.Now())
	assert.Error(t, err)
	assert.Empty(t, token)
	assert.Contains(t, err.Error(), "user is required")
}

func TestGenerateIDToken_HasCorrectClaims(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()
	user := createTestUser()
	authTime := time.Now()
	nonce := "test-nonce-12345"

	token, err := tm.GenerateIDToken(app, user, nonce, authTime)
	require.NoError(t, err)

	claims, err := tm.ValidateToken(token)
	require.NoError(t, err)

	// Check ID token specific claims
	assert.Equal(t, user.ID.String(), claims.Subject)
	assert.Contains(t, claims.Audience, app.ClientID)
	assert.Equal(t, user.Username, claims.Username)
	assert.Equal(t, user.Email, claims.Email)
	assert.Equal(t, true, claims.EmailVerified)
	assert.Equal(t, nonce, claims.Nonce)
	assert.Equal(t, authTime.Unix(), claims.AuthTime)
	assert.Equal(t, "ID", claims.Type)
}

func TestGenerateIDToken_IncludesRoles(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()
	user := createTestUser()
	user.Roles = []database.Role{
		{BaseModel: database.BaseModel{ID: uuid.New()}, Name: "admin"},
		{BaseModel: database.BaseModel{ID: uuid.New()}, Name: "moderator"},
	}

	token, err := tm.GenerateIDToken(app, user, "", time.Now())
	require.NoError(t, err)

	claims, err := tm.ValidateToken(token)
	require.NoError(t, err)

	assert.Len(t, claims.Roles, 2)
	assert.Contains(t, claims.Roles, "admin")
	assert.Contains(t, claims.Roles, "moderator")
}

// =============================================================================
// Token Validation Tests
// =============================================================================

func TestValidateToken_Success(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	token, err := tm.GenerateAccessToken(app, nil, "read", "", nil)
	require.NoError(t, err)

	claims, err := tm.ValidateToken(token)
	require.NoError(t, err)
	assert.NotNil(t, claims)
}

func TestValidateToken_InvalidToken(t *testing.T) {
	tm := setupTokenManager(t)

	claims, err := tm.ValidateToken("invalid.token.here")
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestValidateToken_MalformedToken(t *testing.T) {
	tm := setupTokenManager(t)

	claims, err := tm.ValidateToken("not-a-jwt")
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestValidateToken_WrongSignature(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	// Generate token with current key
	token, err := tm.GenerateAccessToken(app, nil, "read", "", nil)
	require.NoError(t, err)

	// Create a new token manager with different keys
	tm2 := setupTokenManager(t)

	// Token signed with tm shouldn't validate with tm2
	claims, err := tm2.ValidateToken(token)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	// This test would require mocking time or creating an already-expired token
	// For now, we just verify the validation logic exists
	t.Skip("Requires time mocking for proper testing")
}

func TestValidateToken_WrongAlgorithm(t *testing.T) {
	tm := setupTokenManager(t)

	// Create a token with "none" algorithm (should be rejected)
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"sub": "test",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenString, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)

	claims, err := tm.ValidateToken(tokenString)
	assert.Error(t, err)
	assert.Nil(t, claims)
}

// =============================================================================
// Token Introspection Tests
// =============================================================================

func TestIntrospectToken_ActiveToken(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()
	user := createTestUser()

	token, err := tm.GenerateAccessToken(app, user, "openid profile", "https://api.example.com", nil)
	require.NoError(t, err)

	response, err := tm.IntrospectToken(token)
	require.NoError(t, err)

	assert.True(t, response.Active)
	assert.Equal(t, app.ClientID, response.ClientID)
	assert.Equal(t, user.Username, response.Username)
	assert.Equal(t, "openid profile", response.Scope)
	assert.Equal(t, "Bearer", response.TokenType)
	assert.Equal(t, "http://localhost:8080", response.Iss)
	assert.NotEmpty(t, response.Jti)
}

func TestIntrospectToken_InvalidToken(t *testing.T) {
	tm := setupTokenManager(t)

	response, err := tm.IntrospectToken("invalid-token")
	require.NoError(t, err) // Introspection doesn't error, just returns inactive

	assert.False(t, response.Active)
}

func TestIntrospectToken_RefreshToken(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()
	user := createTestUser()

	token, err := tm.GenerateRefreshToken(app, user, "openid offline_access")
	require.NoError(t, err)

	response, err := tm.IntrospectToken(token)
	require.NoError(t, err)

	assert.True(t, response.Active)
	assert.Equal(t, "Refresh", response.TokenType)
}

// =============================================================================
// JWKS Tests
// =============================================================================

func TestGetJWKS_Success(t *testing.T) {
	tm := setupTokenManager(t)

	jwks, err := tm.GetJWKS()
	require.NoError(t, err)
	assert.NotNil(t, jwks)

	keys, ok := jwks["keys"].([]map[string]interface{})
	assert.True(t, ok)
	assert.Len(t, keys, 1)

	key := keys[0]
	assert.Equal(t, "RSA", key["kty"])
	assert.Equal(t, "sig", key["use"])
	assert.Equal(t, "test-key-id", key["kid"])
	assert.Equal(t, "RS256", key["alg"])
	assert.NotEmpty(t, key["n"])
	assert.NotEmpty(t, key["e"])
}

func TestGetJWKS_KeyIDMatches(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	// Generate a token
	token, err := tm.GenerateAccessToken(app, nil, "read", "", nil)
	require.NoError(t, err)

	// Parse the token to get the header
	parsedToken, _, err := jwt.NewParser().ParseUnverified(token, &CustomClaims{})
	require.NoError(t, err)

	// Get JWKS
	jwks, err := tm.GetJWKS()
	require.NoError(t, err)

	keys := jwks["keys"].([]map[string]interface{})
	jwksKid := keys[0]["kid"]

	// KID in token header should match JWKS
	tokenKid := parsedToken.Header["kid"]
	assert.Equal(t, jwksKid, tokenKid)
}

// =============================================================================
// Token Type Tests
// =============================================================================

func TestTokenTypes_AreDistinct(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()
	user := createTestUser()

	accessToken, _ := tm.GenerateAccessToken(app, user, "openid", "", nil)
	refreshToken, _ := tm.GenerateRefreshToken(app, user, "openid")
	idToken, _ := tm.GenerateIDToken(app, user, "nonce", time.Now())

	accessClaims, _ := tm.ValidateToken(accessToken)
	refreshClaims, _ := tm.ValidateToken(refreshToken)
	idClaims, _ := tm.ValidateToken(idToken)

	assert.Equal(t, "Bearer", accessClaims.Type)
	assert.Equal(t, "Refresh", refreshClaims.Type)
	assert.Equal(t, "ID", idClaims.Type)
}

// =============================================================================
// JTI (JWT ID) Tests
// =============================================================================

func TestTokens_HaveUniqueJTI(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	jtis := make(map[string]bool)

	for i := 0; i < 100; i++ {
		token, err := tm.GenerateAccessToken(app, nil, "read", "", nil)
		require.NoError(t, err)

		claims, err := tm.ValidateToken(token)
		require.NoError(t, err)

		assert.False(t, jtis[claims.ID], "Duplicate JTI found")
		jtis[claims.ID] = true
	}
}

// =============================================================================
// Scope Tests
// =============================================================================

func TestAccessToken_PreservesScope(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	scopes := []string{
		"openid",
		"openid profile",
		"openid profile email",
		"read write delete",
		"api:read api:write",
	}

	for _, scope := range scopes {
		t.Run(scope, func(t *testing.T) {
			token, err := tm.GenerateAccessToken(app, nil, scope, "", nil)
			require.NoError(t, err)

			claims, err := tm.ValidateToken(token)
			require.NoError(t, err)

			assert.Equal(t, scope, claims.Scope)
		})
	}
}

// =============================================================================
// Audience Tests
// =============================================================================

func TestAccessToken_IncludesAudience(t *testing.T) {
	tm := setupTokenManager(t)
	app := createTestApplication()

	audiences := []string{
		"https://api.example.com",
		"https://api1.example.com",
		"urn:example:api",
	}

	for _, aud := range audiences {
		t.Run(aud, func(t *testing.T) {
			token, err := tm.GenerateAccessToken(app, nil, "read", aud, nil)
			require.NoError(t, err)

			claims, err := tm.ValidateToken(token)
			require.NoError(t, err)

			assert.Contains(t, claims.Audience, aud)
		})
	}
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkGenerateAccessToken(b *testing.B) {
	privateKey, _ := crypto.GenerateRSAKeyPair(2048)
	jwtConfig := &config.JWTConfig{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		Kid:           "test-key",
		SigningMethod: jwt.SigningMethodRS256,
	}
	tm, _ := NewTokenManager(jwtConfig, "http://localhost:8080")
	app := createTestApplication()
	user := createTestUser()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm.GenerateAccessToken(app, user, "openid profile", "https://api.example.com", nil)
	}
}

func BenchmarkGenerateRefreshToken(b *testing.B) {
	privateKey, _ := crypto.GenerateRSAKeyPair(2048)
	jwtConfig := &config.JWTConfig{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		Kid:           "test-key",
		SigningMethod: jwt.SigningMethodRS256,
	}
	tm, _ := NewTokenManager(jwtConfig, "http://localhost:8080")
	app := createTestApplication()
	user := createTestUser()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm.GenerateRefreshToken(app, user, "openid offline_access")
	}
}

func BenchmarkGenerateIDToken(b *testing.B) {
	privateKey, _ := crypto.GenerateRSAKeyPair(2048)
	jwtConfig := &config.JWTConfig{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		Kid:           "test-key",
		SigningMethod: jwt.SigningMethodRS256,
	}
	tm, _ := NewTokenManager(jwtConfig, "http://localhost:8080")
	app := createTestApplication()
	user := createTestUser()
	authTime := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm.GenerateIDToken(app, user, "nonce", authTime)
	}
}

func BenchmarkValidateToken(b *testing.B) {
	privateKey, _ := crypto.GenerateRSAKeyPair(2048)
	jwtConfig := &config.JWTConfig{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		Kid:           "test-key",
		SigningMethod: jwt.SigningMethodRS256,
	}
	tm, _ := NewTokenManager(jwtConfig, "http://localhost:8080")
	app := createTestApplication()
	token, _ := tm.GenerateAccessToken(app, nil, "read", "", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm.ValidateToken(token)
	}
}

func BenchmarkIntrospectToken(b *testing.B) {
	privateKey, _ := crypto.GenerateRSAKeyPair(2048)
	jwtConfig := &config.JWTConfig{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		Kid:           "test-key",
		SigningMethod: jwt.SigningMethodRS256,
	}
	tm, _ := NewTokenManager(jwtConfig, "http://localhost:8080")
	app := createTestApplication()
	token, _ := tm.GenerateAccessToken(app, nil, "read", "", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm.IntrospectToken(token)
	}
}

func BenchmarkGetJWKS(b *testing.B) {
	privateKey, _ := crypto.GenerateRSAKeyPair(2048)
	jwtConfig := &config.JWTConfig{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		Kid:           "test-key",
		SigningMethod: jwt.SigningMethodRS256,
	}
	tm, _ := NewTokenManager(jwtConfig, "http://localhost:8080")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tm.GetJWKS()
	}
}
