package oauth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tiiuae/oryxid/internal/database"
	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// Test Helpers
// =============================================================================

func createDeviceCodeApplication(t *testing.T, db interface{ Create(interface{}) interface{ Error() error } }) *database.Application {
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	require.NoError(t, err)

	app := &database.Application{
		Name:                    "Device App",
		ClientID:                "device-client-id",
		HashedClientSecret:      string(hashedSecret),
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
		GrantTypes: database.StringArray{
			"urn:ietf:params:oauth:grant-type:device_code",
			"authorization_code",
			"refresh_token",
		},
		ResponseTypes: database.StringArray{"code"},
		RedirectURIs:  database.StringArray{"https://example.com/callback"},
	}

	return app
}

func createTokenExchangeApplication(t *testing.T, db interface{ Create(interface{}) interface{ Error() error } }) *database.Application {
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	require.NoError(t, err)

	app := &database.Application{
		Name:                    "Token Exchange App",
		ClientID:                "exchange-client-id",
		HashedClientSecret:      string(hashedSecret),
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: database.StringArray{
			"urn:ietf:params:oauth:grant-type:token-exchange",
			"client_credentials",
		},
		ResponseTypes: database.StringArray{"code"},
		RedirectURIs:  database.StringArray{"https://example.com/callback"},
	}

	return app
}

func createCIBAApplication(t *testing.T, db interface{ Create(interface{}) interface{ Error() error } }) *database.Application {
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	require.NoError(t, err)

	app := &database.Application{
		Name:                    "CIBA App",
		ClientID:                "ciba-client-id",
		HashedClientSecret:      string(hashedSecret),
		ClientType:              "confidential",
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: database.StringArray{
			"urn:openid:params:grant-type:ciba",
			"authorization_code",
		},
		ResponseTypes: database.StringArray{"code"},
		RedirectURIs:  database.StringArray{"https://example.com/callback"},
	}

	return app
}

// =============================================================================
// Device Authorization Grant Tests (RFC 8628)
// =============================================================================

func TestDeviceAuthorization_CreateRequest(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Create application with device_code grant
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "Device App",
		ClientID:           "device-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "public",
		GrantTypes:         database.StringArray{"urn:ietf:params:oauth:grant-type:device_code"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	err := db.Create(app).Error
	require.NoError(t, err)

	// Create scopes
	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)
	db.Model(app).Association("Scopes").Append(scope)

	req := &DeviceAuthorizationRequest{
		ClientID: app.ClientID,
		Scope:    "openid",
	}

	resp, err := server.CreateDeviceAuthorization(req, "https://example.com/device", "192.168.1.1")
	require.NoError(t, err)

	assert.NotEmpty(t, resp.DeviceCode)
	assert.NotEmpty(t, resp.UserCode)
	assert.Equal(t, "https://example.com/device", resp.VerificationURI)
	assert.Contains(t, resp.VerificationURIComplete, resp.UserCode)
	assert.Equal(t, 1800, resp.ExpiresIn)
	assert.Equal(t, 5, resp.Interval)

	// Verify user code format (XXXX-XXXX)
	assert.Regexp(t, `^[A-Z0-9]{4}-[A-Z0-9]{4}$`, resp.UserCode)
}

func TestDeviceAuthorization_InvalidGrantType(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Create application without device_code grant
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "No Device App",
		ClientID:           "no-device-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"authorization_code"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	err := db.Create(app).Error
	require.NoError(t, err)

	req := &DeviceAuthorizationRequest{
		ClientID: app.ClientID,
	}

	_, err = server.CreateDeviceAuthorization(req, "https://example.com/device", "192.168.1.1")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed")
}

func TestDeviceCode_AuthorizeFlow(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "Device App",
		ClientID:           "device-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "public",
		GrantTypes:         database.StringArray{"urn:ietf:params:oauth:grant-type:device_code"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)
	db.Model(app).Association("Scopes").Append(scope)

	user := createTestUser(t, db)

	// Create device authorization
	req := &DeviceAuthorizationRequest{
		ClientID: app.ClientID,
		Scope:    "openid",
	}
	devResp, err := server.CreateDeviceAuthorization(req, "https://example.com/device", "192.168.1.1")
	require.NoError(t, err)

	// Poll before authorization - should get pending
	tokenReq := &TokenRequest{
		GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
		ClientID:   app.ClientID,
		DeviceCode: devResp.DeviceCode,
	}

	_, err = server.DeviceCodeGrant(tokenReq)
	require.Error(t, err)
	dcErr, ok := err.(*DeviceCodeError)
	require.True(t, ok)
	assert.Equal(t, "authorization_pending", dcErr.Code)

	// Authorize the device code
	err = server.AuthorizeDeviceCode(devResp.UserCode, user)
	require.NoError(t, err)

	// Wait for polling interval (device codes have 5 second interval by default)
	time.Sleep(6 * time.Second)

	// Poll after authorization - should succeed
	tokenResp, err := server.DeviceCodeGrant(tokenReq)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.NotEmpty(t, tokenResp.RefreshToken)
}

func TestDeviceCode_DenyFlow(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "Device App",
		ClientID:           "device-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "public",
		GrantTypes:         database.StringArray{"urn:ietf:params:oauth:grant-type:device_code"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)
	db.Model(app).Association("Scopes").Append(scope)

	// Create device authorization
	req := &DeviceAuthorizationRequest{
		ClientID: app.ClientID,
		Scope:    "openid",
	}
	devResp, err := server.CreateDeviceAuthorization(req, "https://example.com/device", "192.168.1.1")
	require.NoError(t, err)

	// Deny the device code
	err = server.DenyDeviceCode(devResp.UserCode)
	require.NoError(t, err)

	// Poll after denial - should get access_denied
	tokenReq := &TokenRequest{
		GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
		ClientID:   app.ClientID,
		DeviceCode: devResp.DeviceCode,
	}

	_, err = server.DeviceCodeGrant(tokenReq)
	require.Error(t, err)
	dcErr, ok := err.(*DeviceCodeError)
	require.True(t, ok)
	assert.Equal(t, "access_denied", dcErr.Code)
}

func TestDeviceCode_Expiration(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "Device App",
		ClientID:           "device-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "public",
		GrantTypes:         database.StringArray{"urn:ietf:params:oauth:grant-type:device_code"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	// Create expired device code directly
	dc := &database.DeviceCode{
		DeviceCode:      "expired-device-code",
		UserCode:        "EXPI-RED1",
		ApplicationID:   app.ID,
		VerificationURI: "https://example.com/device",
		ExpiresAt:       time.Now().Add(-1 * time.Minute),
		Status:          "pending",
		Interval:        5,
	}
	db.Create(dc)

	tokenReq := &TokenRequest{
		GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
		ClientID:   app.ClientID,
		DeviceCode: "expired-device-code",
	}

	_, err := server.DeviceCodeGrant(tokenReq)
	require.Error(t, err)
	dcErr, ok := err.(*DeviceCodeError)
	require.True(t, ok)
	assert.Equal(t, "expired_token", dcErr.Code)
}

// =============================================================================
// Token Exchange Tests (RFC 8693)
// =============================================================================

func TestTokenExchange_AccessTokenToAccessToken(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "Exchange App",
		ClientID:           "exchange-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"urn:ietf:params:oauth:grant-type:token-exchange", "client_credentials"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)
	db.Model(app).Association("Scopes").Append(scope)

	// Generate subject token
	subjectToken, err := tm.GenerateAccessToken(app, nil, "openid profile", "", nil)
	require.NoError(t, err)

	req := &TokenRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:         app.ClientID,
		ClientSecret:     "test-secret",
		SubjectToken:     subjectToken,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            "openid",
	}

	resp, err := server.TokenExchangeGrant(req)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, TokenTypeAccessToken, resp.IssuedTokenType)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, "openid", resp.Scope)
}

func TestTokenExchange_WithActorToken(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "Exchange App",
		ClientID:           "exchange-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"urn:ietf:params:oauth:grant-type:token-exchange"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)
	db.Model(app).Association("Scopes").Append(scope)

	user := createTestUser(t, db)

	// Generate subject token (user's token)
	subjectToken, err := tm.GenerateAccessToken(app, user, "openid profile", "", nil)
	require.NoError(t, err)

	// Generate actor token (service acting on behalf of user)
	actorToken, err := tm.GenerateAccessToken(app, nil, "openid", "", nil)
	require.NoError(t, err)

	req := &TokenRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:         app.ClientID,
		ClientSecret:     "test-secret",
		SubjectToken:     subjectToken,
		SubjectTokenType: TokenTypeAccessToken,
		ActorToken:       actorToken,
		ActorTokenType:   TokenTypeAccessToken,
	}

	resp, err := server.TokenExchangeGrant(req)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
}

func TestTokenExchange_ScopeDownscaling(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "Exchange App",
		ClientID:           "exchange-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"urn:ietf:params:oauth:grant-type:token-exchange"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	// Generate subject token with multiple scopes
	subjectToken, err := tm.GenerateAccessToken(app, nil, "openid profile email", "", nil)
	require.NoError(t, err)

	// Request with fewer scopes
	req := &TokenRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:         app.ClientID,
		ClientSecret:     "test-secret",
		SubjectToken:     subjectToken,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            "openid",
	}

	resp, err := server.TokenExchangeGrant(req)
	require.NoError(t, err)
	assert.Equal(t, "openid", resp.Scope)
}

func TestTokenExchange_ScopeEscalationRejected(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "Exchange App",
		ClientID:           "exchange-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"urn:ietf:params:oauth:grant-type:token-exchange"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	// Generate subject token with limited scope
	subjectToken, err := tm.GenerateAccessToken(app, nil, "openid", "", nil)
	require.NoError(t, err)

	// Try to request more scopes than original
	req := &TokenRequest{
		GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:         app.ClientID,
		ClientSecret:     "test-secret",
		SubjectToken:     subjectToken,
		SubjectTokenType: TokenTypeAccessToken,
		Scope:            "openid profile admin",
	}

	_, err = server.TokenExchangeGrant(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestTokenExchange_RefreshTokenType(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "Exchange App",
		ClientID:           "exchange-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"urn:ietf:params:oauth:grant-type:token-exchange"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	// Generate subject token
	subjectToken, err := tm.GenerateAccessToken(app, nil, "openid", "", nil)
	require.NoError(t, err)

	req := &TokenRequest{
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:           app.ClientID,
		ClientSecret:       "test-secret",
		SubjectToken:       subjectToken,
		SubjectTokenType:   TokenTypeAccessToken,
		RequestedTokenType: TokenTypeRefreshToken,
	}

	resp, err := server.TokenExchangeGrant(req)
	require.NoError(t, err)
	assert.Equal(t, TokenTypeRefreshToken, resp.IssuedTokenType)
	assert.Equal(t, "N_A", resp.TokenType) // Per RFC 8693
}

// =============================================================================
// CIBA Tests (Client-Initiated Backchannel Authentication)
// =============================================================================

func TestCIBA_CreateRequest(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "CIBA App",
		ClientID:           "ciba-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"urn:openid:params:grant-type:ciba"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)
	db.Model(app).Association("Scopes").Append(scope)

	user := createTestUser(t, db)

	req := &CIBAAuthenticationRequest{
		ClientID:       app.ClientID,
		Scope:          "openid",
		LoginHint:      user.Username,
		BindingMessage: "Please authorize login from Device XYZ",
	}

	resp, err := server.CreateCIBAAuthentication(req, "test-secret")
	require.NoError(t, err)

	assert.NotEmpty(t, resp.AuthReqID)
	assert.Equal(t, 120, resp.ExpiresIn)
	assert.Equal(t, 5, resp.Interval)
}

func TestCIBA_PollBeforeAuthorization(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "CIBA App",
		ClientID:           "ciba-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"urn:openid:params:grant-type:ciba"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)
	db.Model(app).Association("Scopes").Append(scope)

	user := createTestUser(t, db)

	// Create CIBA request
	cibaReq := &CIBAAuthenticationRequest{
		ClientID:  app.ClientID,
		Scope:     "openid",
		LoginHint: user.Username,
	}
	cibaResp, err := server.CreateCIBAAuthentication(cibaReq, "test-secret")
	require.NoError(t, err)

	// Poll before authorization
	tokenReq := &TokenRequest{
		GrantType:    "urn:openid:params:grant-type:ciba",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		AuthReqID:    cibaResp.AuthReqID,
	}

	_, err = server.CIBAGrant(tokenReq)
	require.Error(t, err)
	cibaErr, ok := err.(*CIBAError)
	require.True(t, ok)
	assert.Equal(t, "authorization_pending", cibaErr.Code)
}

func TestCIBA_AuthorizeAndPoll(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "CIBA App",
		ClientID:           "ciba-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"urn:openid:params:grant-type:ciba"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)
	db.Model(app).Association("Scopes").Append(scope)

	user := createTestUser(t, db)

	// Create CIBA request
	cibaReq := &CIBAAuthenticationRequest{
		ClientID:  app.ClientID,
		Scope:     "openid",
		LoginHint: user.Username,
	}
	cibaResp, err := server.CreateCIBAAuthentication(cibaReq, "test-secret")
	require.NoError(t, err)

	// User authorizes
	err = server.AuthorizeCIBARequest(cibaResp.AuthReqID, user)
	require.NoError(t, err)

	// Poll after authorization
	tokenReq := &TokenRequest{
		GrantType:    "urn:openid:params:grant-type:ciba",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		AuthReqID:    cibaResp.AuthReqID,
	}

	tokenResp, err := server.CIBAGrant(tokenReq)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.NotEmpty(t, tokenResp.RefreshToken)
}

func TestCIBA_DenyRequest(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "CIBA App",
		ClientID:           "ciba-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"urn:openid:params:grant-type:ciba"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)
	db.Model(app).Association("Scopes").Append(scope)

	user := createTestUser(t, db)

	// Create CIBA request
	cibaReq := &CIBAAuthenticationRequest{
		ClientID:  app.ClientID,
		Scope:     "openid",
		LoginHint: user.Username,
	}
	cibaResp, err := server.CreateCIBAAuthentication(cibaReq, "test-secret")
	require.NoError(t, err)

	// User denies
	err = server.DenyCIBARequest(cibaResp.AuthReqID)
	require.NoError(t, err)

	// Poll after denial
	tokenReq := &TokenRequest{
		GrantType:    "urn:openid:params:grant-type:ciba",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		AuthReqID:    cibaResp.AuthReqID,
	}

	_, err = server.CIBAGrant(tokenReq)
	require.Error(t, err)
	cibaErr, ok := err.(*CIBAError)
	require.True(t, ok)
	assert.Equal(t, "access_denied", cibaErr.Code)
}

func TestCIBA_UserNotFound(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Setup
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "CIBA App",
		ClientID:           "ciba-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"urn:openid:params:grant-type:ciba"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	req := &CIBAAuthenticationRequest{
		ClientID:  app.ClientID,
		Scope:     "openid",
		LoginHint: "nonexistent-user",
	}

	_, err := server.CreateCIBAAuthentication(req, "test-secret")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// =============================================================================
// Rich Authorization Requests Tests (RFC 9396)
// =============================================================================

func TestRAR_AuthorizationCodeFlow(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	app := createTestApplication(t, db)
	user := createTestUser(t, db)

	// Authorization details for payment
	authDetails := `[{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"123.50"},"creditorName":"Merchant123"}]`

	req := &AuthorizeRequest{
		ResponseType:         "code",
		ClientID:             app.ClientID,
		RedirectURI:          "https://example.com/callback",
		Scope:                "openid",
		State:                "test-state",
		AuthorizationDetails: authDetails,
	}

	code, err := server.GenerateAuthorizationCode(app, user, req)
	require.NoError(t, err)
	assert.NotEmpty(t, code)

	// Verify authorization_details is stored
	var authCode database.AuthorizationCode
	err = db.Where("code = ?", code).First(&authCode).Error
	require.NoError(t, err)
	assert.Equal(t, authDetails, authCode.AuthorizationDetails)
}

func TestRAR_TokenResponse(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	app := createTestApplication(t, db)
	user := createTestUser(t, db)

	// Authorization details
	authDetails := `[{"type":"account_information","actions":["read"],"locations":["https://api.bank.com/accounts"]}]`

	// Create authorization code with RAR
	authReq := &AuthorizeRequest{
		ResponseType:         "code",
		ClientID:             app.ClientID,
		RedirectURI:          "https://example.com/callback",
		Scope:                "openid",
		State:                "test-state",
		CodeChallenge:        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod:  "S256",
		AuthorizationDetails: authDetails,
	}

	code, err := server.GenerateAuthorizationCode(app, user, authReq)
	require.NoError(t, err)

	// Exchange code for tokens
	tokenReq := &TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}

	tokenResp, err := server.ExchangeAuthorizationCode(tokenReq)
	require.NoError(t, err)

	assert.NotEmpty(t, tokenResp.AccessToken)
	assert.Equal(t, authDetails, tokenResp.AuthorizationDetails)
}

func TestRAR_PARWithAuthorizationDetails(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	app := createTestApplication(t, db)

	authDetails := `[{"type":"openid_credential","credential_configuration_id":"UniversityDegreeCredential"}]`

	req := &AuthorizeRequest{
		ResponseType:         "code",
		ClientID:             app.ClientID,
		RedirectURI:          "https://example.com/callback",
		Scope:                "openid",
		State:                "test-state",
		AuthorizationDetails: authDetails,
	}

	parResp, err := server.CreatePushedAuthorizationRequest(req, "test-secret")
	require.NoError(t, err)

	// Validate PAR includes authorization_details
	par, err := server.ValidatePAR(parResp.RequestURI, app.ClientID)
	require.NoError(t, err)
	assert.Equal(t, authDetails, par.AuthorizationDetails)
}

func TestRAR_JSONValidation(t *testing.T) {
	// Test that authorization_details is properly preserved as JSON
	authDetails := []map[string]interface{}{
		{
			"type": "payment_initiation",
			"instructedAmount": map[string]string{
				"currency": "USD",
				"amount":   "500.00",
			},
			"creditorName":    "Test Merchant",
			"creditorAccount": "DE89370400440532013000",
		},
	}

	jsonBytes, err := json.Marshal(authDetails)
	require.NoError(t, err)

	// Verify it can be unmarshaled back
	var parsed []map[string]interface{}
	err = json.Unmarshal(jsonBytes, &parsed)
	require.NoError(t, err)

	assert.Equal(t, "payment_initiation", parsed[0]["type"])
	instructedAmount := parsed[0]["instructedAmount"].(map[string]interface{})
	assert.Equal(t, "USD", instructedAmount["currency"])
}

// =============================================================================
// Basic OAuth Flow Tests
// =============================================================================

func TestClientCredentialsGrant(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	app := createTestApplication(t, db)

	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)
	db.Model(app).Association("Scopes").Append(scope)

	req := &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		Scope:        "openid",
	}

	resp, err := server.ClientCredentialsGrant(req)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Equal(t, 3600, resp.ExpiresIn)
}

func TestPasswordGrant(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Create app with password grant
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("test-secret"), bcrypt.DefaultCost)
	app := &database.Application{
		Name:               "Password App",
		ClientID:           "password-client",
		HashedClientSecret: string(hashedSecret),
		ClientType:         "confidential",
		GrantTypes:         database.StringArray{"password"},
		RedirectURIs:       database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)

	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)
	db.Model(app).Association("Scopes").Append(scope)

	user := createTestUser(t, db)

	req := &TokenRequest{
		GrantType:    "password",
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		Username:     user.Username,
		Password:     "password123",
		Scope:        "openid",
	}

	resp, err := server.PasswordGrant(req)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}

func TestAuthorizationCodeExchange(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	app := createTestApplication(t, db)
	user := createTestUser(t, db)

	// Create authorization code
	authReq := &AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            app.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		State:               "test-state",
		Nonce:               "test-nonce",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}

	code, err := server.GenerateAuthorizationCode(app, user, authReq)
	require.NoError(t, err)

	// Exchange code for tokens
	tokenReq := &TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}

	resp, err := server.ExchangeAuthorizationCode(tokenReq)
	require.NoError(t, err)

	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.NotEmpty(t, resp.IDToken) // Because openid scope
	assert.Equal(t, "openid profile", resp.Scope)
}

func TestCodeReuse(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	app := createTestApplication(t, db)
	user := createTestUser(t, db)

	authReq := &AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            app.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}

	code, err := server.GenerateAuthorizationCode(app, user, authReq)
	require.NoError(t, err)

	tokenReq := &TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		ClientID:     app.ClientID,
		ClientSecret: "test-secret",
		RedirectURI:  "https://example.com/callback",
		CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}

	// First use - should succeed
	_, err = server.ExchangeAuthorizationCode(tokenReq)
	require.NoError(t, err)

	// Second use - should fail
	_, err = server.ExchangeAuthorizationCode(tokenReq)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already used")
}

// =============================================================================
// Error Cases
// =============================================================================

func TestInvalidClient(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	req := &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     "nonexistent-client",
		ClientSecret: "secret",
	}

	_, err := server.ClientCredentialsGrant(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid client")
}

func TestInvalidClientSecret(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	app := createTestApplication(t, db)

	req := &TokenRequest{
		GrantType:    "client_credentials",
		ClientID:     app.ClientID,
		ClientSecret: "wrong-secret",
	}

	_, err := server.ClientCredentialsGrant(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid client")
}

func TestInvalidRedirectURI(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	app := createTestApplication(t, db)

	req := &AuthorizeRequest{
		ResponseType: "code",
		ClientID:     app.ClientID,
		RedirectURI:  "https://malicious.com/callback",
		Scope:        "openid",
	}

	_, err := server.ValidateAuthorizationRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid redirect")
}

func TestPKCERequired(t *testing.T) {
	db := setupTestDB(t)
	tm := createTestTokenManager(t)
	server := NewServer(db, tm)

	// Create scope first
	scope := &database.Scope{Name: "openid", IsDefault: true}
	db.Create(scope)

	// Create public client (requires PKCE)
	app := &database.Application{
		Name:          "Public App",
		ClientID:      "public-client",
		ClientType:    "public",
		GrantTypes:    database.StringArray{"authorization_code"},
		ResponseTypes: database.StringArray{"code"},
		RedirectURIs:  database.StringArray{"https://example.com/callback"},
	}
	db.Create(app)
	db.Model(app).Association("Scopes").Append(scope)

	req := &AuthorizeRequest{
		ResponseType: "code",
		ClientID:     app.ClientID,
		RedirectURI:  "https://example.com/callback",
		Scope:        "openid",
		// No PKCE challenge
	}

	_, err := server.ValidateAuthorizationRequest(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "PKCE")
}
