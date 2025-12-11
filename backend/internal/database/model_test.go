package database

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	err = db.AutoMigrate(
		&User{},
		&Role{},
		&Permission{},
		&Application{},
		&Scope{},
		&Audience{},
		&AuthorizationCode{},
		&Token{},
		&Session{},
		&AuditLog{},
		&SigningKey{},
		&PushedAuthorizationRequest{},
	)
	require.NoError(t, err)

	return db
}

// =============================================================================
// StringArray Tests
// =============================================================================

func TestStringArray_Scan_Nil(t *testing.T) {
	var arr StringArray
	err := arr.Scan(nil)
	require.NoError(t, err)
	assert.Empty(t, arr)
	assert.Equal(t, []string{}, []string(arr))
}

func TestStringArray_Scan_ValidJSON(t *testing.T) {
	var arr StringArray
	jsonData := []byte(`["one", "two", "three"]`)
	err := arr.Scan(jsonData)
	require.NoError(t, err)
	assert.Len(t, arr, 3)
	assert.Equal(t, "one", arr[0])
	assert.Equal(t, "two", arr[1])
	assert.Equal(t, "three", arr[2])
}

func TestStringArray_Scan_EmptyArray(t *testing.T) {
	var arr StringArray
	jsonData := []byte(`[]`)
	err := arr.Scan(jsonData)
	require.NoError(t, err)
	assert.Empty(t, arr)
}

func TestStringArray_Scan_InvalidType(t *testing.T) {
	var arr StringArray
	err := arr.Scan("not bytes")
	require.NoError(t, err) // Returns nil error for non-byte types
	assert.Empty(t, arr)
}

func TestStringArray_Value_NonEmpty(t *testing.T) {
	arr := StringArray{"one", "two", "three"}
	val, err := arr.Value()
	require.NoError(t, err)

	var result []string
	err = json.Unmarshal(val.([]byte), &result)
	require.NoError(t, err)
	assert.Equal(t, []string{"one", "two", "three"}, result)
}

func TestStringArray_Value_Empty(t *testing.T) {
	var arr StringArray
	val, err := arr.Value()
	require.NoError(t, err)

	var result []string
	err = json.Unmarshal(val.([]byte), &result)
	require.NoError(t, err)
	assert.Equal(t, []string{}, result)
}

// =============================================================================
// JSONB Tests
// =============================================================================

func TestJSONB_Value_Nil(t *testing.T) {
	var j JSONB
	val, err := j.Value()
	require.NoError(t, err)
	assert.Nil(t, val)
}

func TestJSONB_Value_NonNil(t *testing.T) {
	j := JSONB{"key": "value", "number": 42}
	val, err := j.Value()
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(val.([]byte), &result)
	require.NoError(t, err)
	assert.Equal(t, "value", result["key"])
	assert.Equal(t, float64(42), result["number"])
}

func TestJSONB_Scan_Nil(t *testing.T) {
	var j JSONB
	err := j.Scan(nil)
	require.NoError(t, err)
	assert.Nil(t, j)
}

func TestJSONB_Scan_ValidJSON(t *testing.T) {
	var j JSONB
	jsonData := []byte(`{"key": "value", "nested": {"inner": true}}`)
	err := j.Scan(jsonData)
	require.NoError(t, err)

	assert.Equal(t, "value", j["key"])
	nested := j["nested"].(map[string]interface{})
	assert.Equal(t, true, nested["inner"])
}

func TestJSONB_Scan_InvalidType(t *testing.T) {
	var j JSONB
	err := j.Scan("not bytes")
	assert.Error(t, err)
}

// =============================================================================
// BaseModel Tests
// =============================================================================

func TestBaseModel_BeforeCreate_GeneratesUUID(t *testing.T) {
	db := setupTestDB(t)

	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "hashedpassword",
	}

	err := db.Create(user).Error
	require.NoError(t, err)

	assert.NotEqual(t, uuid.Nil, user.ID)
	assert.NotZero(t, user.CreatedAt)
	assert.NotZero(t, user.UpdatedAt)
}

func TestBaseModel_BeforeCreate_PreservesExistingUUID(t *testing.T) {
	db := setupTestDB(t)

	existingID := uuid.New()
	user := &User{
		BaseModel: BaseModel{ID: existingID},
		Username:  "testuser",
		Email:     "test@example.com",
		Password:  "hashedpassword",
	}

	err := db.Create(user).Error
	require.NoError(t, err)

	assert.Equal(t, existingID, user.ID)
}

// =============================================================================
// User Model Tests
// =============================================================================

func TestUser_Create(t *testing.T) {
	db := setupTestDB(t)

	user := &User{
		Username:      "testuser",
		Email:         "test@example.com",
		EmailVerified: true,
		Password:      "hashedpassword",
		IsActive:      true,
		IsAdmin:       false,
	}

	err := db.Create(user).Error
	require.NoError(t, err)

	// Retrieve and verify
	var retrieved User
	err = db.First(&retrieved, user.ID).Error
	require.NoError(t, err)

	assert.Equal(t, "testuser", retrieved.Username)
	assert.Equal(t, "test@example.com", retrieved.Email)
	assert.True(t, retrieved.EmailVerified)
	assert.True(t, retrieved.IsActive)
	assert.False(t, retrieved.IsAdmin)
}

func TestUser_UniqueUsername(t *testing.T) {
	db := setupTestDB(t)

	user1 := &User{
		Username: "unique",
		Email:    "user1@example.com",
		Password: "password",
	}
	err := db.Create(user1).Error
	require.NoError(t, err)

	user2 := &User{
		Username: "unique", // Same username
		Email:    "user2@example.com",
		Password: "password",
	}
	err = db.Create(user2).Error
	assert.Error(t, err) // Should fail due to unique constraint
}

func TestUser_UniqueEmail(t *testing.T) {
	db := setupTestDB(t)

	user1 := &User{
		Username: "user1",
		Email:    "same@example.com",
		Password: "password",
	}
	err := db.Create(user1).Error
	require.NoError(t, err)

	user2 := &User{
		Username: "user2",
		Email:    "same@example.com", // Same email
		Password: "password",
	}
	err = db.Create(user2).Error
	assert.Error(t, err) // Should fail due to unique constraint
}

func TestUser_WithRoles(t *testing.T) {
	db := setupTestDB(t)

	// Create role
	role := &Role{Name: "admin", Description: "Administrator"}
	err := db.Create(role).Error
	require.NoError(t, err)

	// Create user with role
	user := &User{
		Username: "adminuser",
		Email:    "admin@example.com",
		Password: "password",
		Roles:    []Role{*role},
	}
	err = db.Create(user).Error
	require.NoError(t, err)

	// Retrieve with preload
	var retrieved User
	err = db.Preload("Roles").First(&retrieved, user.ID).Error
	require.NoError(t, err)

	assert.Len(t, retrieved.Roles, 1)
	assert.Equal(t, "admin", retrieved.Roles[0].Name)
}

// =============================================================================
// Role Model Tests
// =============================================================================

func TestRole_Create(t *testing.T) {
	db := setupTestDB(t)

	role := &Role{
		Name:        "admin",
		Description: "Administrator role",
	}

	err := db.Create(role).Error
	require.NoError(t, err)

	var retrieved Role
	err = db.First(&retrieved, role.ID).Error
	require.NoError(t, err)

	assert.Equal(t, "admin", retrieved.Name)
	assert.Equal(t, "Administrator role", retrieved.Description)
}

func TestRole_UniqueName(t *testing.T) {
	db := setupTestDB(t)

	role1 := &Role{Name: "unique-role"}
	err := db.Create(role1).Error
	require.NoError(t, err)

	role2 := &Role{Name: "unique-role"}
	err = db.Create(role2).Error
	assert.Error(t, err)
}

func TestRole_WithPermissions(t *testing.T) {
	db := setupTestDB(t)

	permission := &Permission{Name: "read:users", Description: "Read users"}
	err := db.Create(permission).Error
	require.NoError(t, err)

	role := &Role{
		Name:        "reader",
		Permissions: []Permission{*permission},
	}
	err = db.Create(role).Error
	require.NoError(t, err)

	var retrieved Role
	err = db.Preload("Permissions").First(&retrieved, role.ID).Error
	require.NoError(t, err)

	assert.Len(t, retrieved.Permissions, 1)
	assert.Equal(t, "read:users", retrieved.Permissions[0].Name)
}

// =============================================================================
// Application Model Tests
// =============================================================================

func TestApplication_Create(t *testing.T) {
	db := setupTestDB(t)

	app := &Application{
		Name:                     "Test App",
		Description:              "A test application",
		ClientID:                 "test-client-id",
		HashedClientSecret:       "hashed-secret",
		ClientType:               "confidential",
		TokenEndpointAuthMethod:  "client_secret_basic",
		GrantTypes:               StringArray{"authorization_code", "refresh_token"},
		ResponseTypes:            StringArray{"code"},
		RedirectURIs:             StringArray{"https://example.com/callback"},
		PostLogoutURIs:           StringArray{"https://example.com/logout"},
		SkipAuthorization:        false,
		AccessTokenLifespan:      3600,
		RefreshTokenLifespan:     86400,
	}

	err := db.Create(app).Error
	require.NoError(t, err)

	var retrieved Application
	err = db.First(&retrieved, app.ID).Error
	require.NoError(t, err)

	assert.Equal(t, "Test App", retrieved.Name)
	assert.Equal(t, "test-client-id", retrieved.ClientID)
	assert.Equal(t, "confidential", retrieved.ClientType)
	assert.Len(t, retrieved.GrantTypes, 2)
	assert.Contains(t, []string(retrieved.GrantTypes), "authorization_code")
	assert.Len(t, retrieved.RedirectURIs, 1)
}

func TestApplication_UniqueClientID(t *testing.T) {
	db := setupTestDB(t)

	app1 := &Application{
		Name:         "App 1",
		ClientID:     "same-client-id",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"client_credentials"},
		RedirectURIs: StringArray{"https://example.com"},
	}
	err := db.Create(app1).Error
	require.NoError(t, err)

	app2 := &Application{
		Name:         "App 2",
		ClientID:     "same-client-id",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"client_credentials"},
		RedirectURIs: StringArray{"https://example2.com"},
	}
	err = db.Create(app2).Error
	assert.Error(t, err)
}

func TestApplication_WithScopes(t *testing.T) {
	db := setupTestDB(t)

	scope := &Scope{Name: "read", Description: "Read access"}
	err := db.Create(scope).Error
	require.NoError(t, err)

	app := &Application{
		Name:         "App with Scopes",
		ClientID:     "scoped-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"client_credentials"},
		RedirectURIs: StringArray{"https://example.com"},
		Scopes:       []Scope{*scope},
	}
	err = db.Create(app).Error
	require.NoError(t, err)

	var retrieved Application
	err = db.Preload("Scopes").First(&retrieved, app.ID).Error
	require.NoError(t, err)

	assert.Len(t, retrieved.Scopes, 1)
	assert.Equal(t, "read", retrieved.Scopes[0].Name)
}

func TestApplication_WithAudiences(t *testing.T) {
	db := setupTestDB(t)

	audience := &Audience{
		Identifier: "https://api.example.com",
		Name:       "Example API",
	}
	err := db.Create(audience).Error
	require.NoError(t, err)

	app := &Application{
		Name:         "App with Audiences",
		ClientID:     "audience-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"client_credentials"},
		RedirectURIs: StringArray{"https://example.com"},
		Audiences:    []Audience{*audience},
	}
	err = db.Create(app).Error
	require.NoError(t, err)

	var retrieved Application
	err = db.Preload("Audiences").First(&retrieved, app.ID).Error
	require.NoError(t, err)

	assert.Len(t, retrieved.Audiences, 1)
	assert.Equal(t, "https://api.example.com", retrieved.Audiences[0].Identifier)
}

func TestApplication_WithOwner(t *testing.T) {
	db := setupTestDB(t)

	owner := &User{
		Username: "owner",
		Email:    "owner@example.com",
		Password: "password",
	}
	err := db.Create(owner).Error
	require.NoError(t, err)

	app := &Application{
		Name:         "Owned App",
		ClientID:     "owned-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"client_credentials"},
		RedirectURIs: StringArray{"https://example.com"},
		OwnerID:      &owner.ID,
	}
	err = db.Create(app).Error
	require.NoError(t, err)

	var retrieved Application
	err = db.Preload("Owner").First(&retrieved, app.ID).Error
	require.NoError(t, err)

	assert.NotNil(t, retrieved.Owner)
	assert.Equal(t, "owner", retrieved.Owner.Username)
}

// =============================================================================
// Scope Model Tests
// =============================================================================

func TestScope_Create(t *testing.T) {
	db := setupTestDB(t)

	scope := &Scope{
		Name:        "read:users",
		Description: "Read user data",
		IsDefault:   true,
	}

	err := db.Create(scope).Error
	require.NoError(t, err)

	var retrieved Scope
	err = db.First(&retrieved, scope.ID).Error
	require.NoError(t, err)

	assert.Equal(t, "read:users", retrieved.Name)
	assert.Equal(t, "Read user data", retrieved.Description)
	assert.True(t, retrieved.IsDefault)
}

func TestScope_UniqueName(t *testing.T) {
	db := setupTestDB(t)

	scope1 := &Scope{Name: "unique-scope"}
	err := db.Create(scope1).Error
	require.NoError(t, err)

	scope2 := &Scope{Name: "unique-scope"}
	err = db.Create(scope2).Error
	assert.Error(t, err)
}

// =============================================================================
// Audience Model Tests
// =============================================================================

func TestAudience_Create(t *testing.T) {
	db := setupTestDB(t)

	audience := &Audience{
		Identifier:  "https://api.example.com",
		Name:        "Example API",
		Description: "The main API",
	}

	err := db.Create(audience).Error
	require.NoError(t, err)

	var retrieved Audience
	err = db.First(&retrieved, audience.ID).Error
	require.NoError(t, err)

	assert.Equal(t, "https://api.example.com", retrieved.Identifier)
	assert.Equal(t, "Example API", retrieved.Name)
}

func TestAudience_UniqueIdentifier(t *testing.T) {
	db := setupTestDB(t)

	aud1 := &Audience{Identifier: "https://api.example.com", Name: "API 1"}
	err := db.Create(aud1).Error
	require.NoError(t, err)

	aud2 := &Audience{Identifier: "https://api.example.com", Name: "API 2"}
	err = db.Create(aud2).Error
	assert.Error(t, err)
}

func TestAudience_WithScopes(t *testing.T) {
	db := setupTestDB(t)

	scope := &Scope{Name: "api:read"}
	err := db.Create(scope).Error
	require.NoError(t, err)

	audience := &Audience{
		Identifier: "https://api.example.com",
		Name:       "API with Scopes",
		Scopes:     []Scope{*scope},
	}
	err = db.Create(audience).Error
	require.NoError(t, err)

	var retrieved Audience
	err = db.Preload("Scopes").First(&retrieved, audience.ID).Error
	require.NoError(t, err)

	assert.Len(t, retrieved.Scopes, 1)
}

// =============================================================================
// AuthorizationCode Model Tests
// =============================================================================

func TestAuthorizationCode_Create(t *testing.T) {
	db := setupTestDB(t)

	app := &Application{
		Name:         "Test App",
		ClientID:     "test-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"authorization_code"},
		RedirectURIs: StringArray{"https://example.com/callback"},
	}
	err := db.Create(app).Error
	require.NoError(t, err)

	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "password",
	}
	err = db.Create(user).Error
	require.NoError(t, err)

	authCode := &AuthorizationCode{
		Code:                "test-auth-code-12345",
		ApplicationID:       app.ID,
		UserID:              &user.ID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		State:               "state123",
		Nonce:               "nonce123",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		Used:                false,
	}

	err = db.Create(authCode).Error
	require.NoError(t, err)

	var retrieved AuthorizationCode
	err = db.Preload("Application").Preload("User").First(&retrieved, authCode.ID).Error
	require.NoError(t, err)

	assert.Equal(t, "test-auth-code-12345", retrieved.Code)
	assert.Equal(t, "openid profile", retrieved.Scope)
	assert.Equal(t, "S256", retrieved.CodeChallengeMethod)
	assert.False(t, retrieved.Used)
}

func TestAuthorizationCode_UniqueCode(t *testing.T) {
	db := setupTestDB(t)

	app := &Application{
		Name:         "Test App",
		ClientID:     "test-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"authorization_code"},
		RedirectURIs: StringArray{"https://example.com"},
	}
	err := db.Create(app).Error
	require.NoError(t, err)

	code1 := &AuthorizationCode{
		Code:          "unique-code",
		ApplicationID: app.ID,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	err = db.Create(code1).Error
	require.NoError(t, err)

	code2 := &AuthorizationCode{
		Code:          "unique-code",
		ApplicationID: app.ID,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	err = db.Create(code2).Error
	assert.Error(t, err)
}

// =============================================================================
// Token Model Tests
// =============================================================================

func TestToken_Create(t *testing.T) {
	db := setupTestDB(t)

	app := &Application{
		Name:         "Test App",
		ClientID:     "test-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"client_credentials"},
		RedirectURIs: StringArray{"https://example.com"},
	}
	err := db.Create(app).Error
	require.NoError(t, err)

	token := &Token{
		TokenHash:     "hashed-token-value",
		TokenType:     "access",
		ApplicationID: app.ID,
		Scope:         "read write",
		ExpiresAt:     time.Now().Add(time.Hour),
		Revoked:       false,
	}

	err = db.Create(token).Error
	require.NoError(t, err)

	var retrieved Token
	err = db.First(&retrieved, token.ID).Error
	require.NoError(t, err)

	assert.Equal(t, "hashed-token-value", retrieved.TokenHash)
	assert.Equal(t, "access", retrieved.TokenType)
	assert.Equal(t, "read write", retrieved.Scope)
	assert.False(t, retrieved.Revoked)
}

func TestToken_UniqueHash(t *testing.T) {
	db := setupTestDB(t)

	app := &Application{
		Name:         "Test App",
		ClientID:     "test-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"client_credentials"},
		RedirectURIs: StringArray{"https://example.com"},
	}
	err := db.Create(app).Error
	require.NoError(t, err)

	token1 := &Token{
		TokenHash:     "same-hash",
		TokenType:     "access",
		ApplicationID: app.ID,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	err = db.Create(token1).Error
	require.NoError(t, err)

	token2 := &Token{
		TokenHash:     "same-hash",
		TokenType:     "access",
		ApplicationID: app.ID,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	err = db.Create(token2).Error
	assert.Error(t, err)
}

func TestToken_Revocation(t *testing.T) {
	db := setupTestDB(t)

	app := &Application{
		Name:         "Test App",
		ClientID:     "test-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"client_credentials"},
		RedirectURIs: StringArray{"https://example.com"},
	}
	err := db.Create(app).Error
	require.NoError(t, err)

	token := &Token{
		TokenHash:     "revocable-token",
		TokenType:     "refresh",
		ApplicationID: app.ID,
		ExpiresAt:     time.Now().Add(time.Hour),
		Revoked:       false,
	}
	err = db.Create(token).Error
	require.NoError(t, err)

	// Revoke the token
	now := time.Now()
	err = db.Model(token).Updates(map[string]interface{}{
		"revoked":    true,
		"revoked_at": now,
	}).Error
	require.NoError(t, err)

	var retrieved Token
	err = db.First(&retrieved, token.ID).Error
	require.NoError(t, err)

	assert.True(t, retrieved.Revoked)
	assert.NotNil(t, retrieved.RevokedAt)
}

// =============================================================================
// Session Model Tests
// =============================================================================

func TestSession_Create(t *testing.T) {
	db := setupTestDB(t)

	user := &User{
		Username: "sessionuser",
		Email:    "session@example.com",
		Password: "password",
	}
	err := db.Create(user).Error
	require.NoError(t, err)

	session := &Session{
		SessionID: "session-12345",
		UserID:    user.ID,
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		LastUsed:  time.Now(),
	}

	err = db.Create(session).Error
	require.NoError(t, err)

	var retrieved Session
	err = db.Preload("User").First(&retrieved, session.ID).Error
	require.NoError(t, err)

	assert.Equal(t, "session-12345", retrieved.SessionID)
	assert.Equal(t, user.ID, retrieved.UserID)
	assert.Equal(t, "192.168.1.1", retrieved.IPAddress)
}

func TestSession_UniqueSessionID(t *testing.T) {
	db := setupTestDB(t)

	user := &User{
		Username: "sessionuser",
		Email:    "session@example.com",
		Password: "password",
	}
	err := db.Create(user).Error
	require.NoError(t, err)

	session1 := &Session{
		SessionID: "unique-session",
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
		LastUsed:  time.Now(),
	}
	err = db.Create(session1).Error
	require.NoError(t, err)

	session2 := &Session{
		SessionID: "unique-session",
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour),
		LastUsed:  time.Now(),
	}
	err = db.Create(session2).Error
	assert.Error(t, err)
}

// =============================================================================
// AuditLog Model Tests
// =============================================================================

func TestAuditLog_Create(t *testing.T) {
	db := setupTestDB(t)

	user := &User{
		Username: "audituser",
		Email:    "audit@example.com",
		Password: "password",
	}
	err := db.Create(user).Error
	require.NoError(t, err)

	audit := &AuditLog{
		UserID:     &user.ID,
		Action:     "user.login",
		Resource:   "user",
		ResourceID: user.ID.String(),
		IPAddress:  "192.168.1.1",
		UserAgent:  "Mozilla/5.0",
		StatusCode: 200,
		Metadata:   JSONB{"method": "POST", "path": "/auth/login"},
	}

	err = db.Create(audit).Error
	require.NoError(t, err)

	var retrieved AuditLog
	err = db.First(&retrieved, audit.ID).Error
	require.NoError(t, err)

	assert.Equal(t, "user.login", retrieved.Action)
	assert.Equal(t, "user", retrieved.Resource)
	assert.Equal(t, 200, retrieved.StatusCode)
	assert.NotNil(t, retrieved.Metadata)
}

func TestAuditLog_WithApplication(t *testing.T) {
	db := setupTestDB(t)

	app := &Application{
		Name:         "Test App",
		ClientID:     "test-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"client_credentials"},
		RedirectURIs: StringArray{"https://example.com"},
	}
	err := db.Create(app).Error
	require.NoError(t, err)

	audit := &AuditLog{
		ApplicationID: &app.ID,
		Action:        "token.issued",
		Resource:      "token",
		StatusCode:    200,
	}

	err = db.Create(audit).Error
	require.NoError(t, err)

	var retrieved AuditLog
	err = db.First(&retrieved, audit.ID).Error
	require.NoError(t, err)

	assert.NotNil(t, retrieved.ApplicationID)
	assert.Equal(t, app.ID, *retrieved.ApplicationID)
}

// =============================================================================
// SigningKey Model Tests
// =============================================================================

func TestSigningKey_Create(t *testing.T) {
	db := setupTestDB(t)

	key := &SigningKey{
		KeyID:         "key-12345",
		Algorithm:     "RS256",
		PrivateKeyPEM: "-----BEGIN RSA PRIVATE KEY-----\n...",
		PublicKeyPEM:  "-----BEGIN PUBLIC KEY-----\n...",
		IsActive:      true,
		ActivatedAt:   time.Now(),
	}

	err := db.Create(key).Error
	require.NoError(t, err)

	var retrieved SigningKey
	err = db.First(&retrieved, key.ID).Error
	require.NoError(t, err)

	assert.Equal(t, "key-12345", retrieved.KeyID)
	assert.Equal(t, "RS256", retrieved.Algorithm)
	assert.True(t, retrieved.IsActive)
}

func TestSigningKey_UniqueKeyID(t *testing.T) {
	db := setupTestDB(t)

	key1 := &SigningKey{
		KeyID:         "unique-key",
		Algorithm:     "RS256",
		PrivateKeyPEM: "private",
		PublicKeyPEM:  "public",
		ActivatedAt:   time.Now(),
	}
	err := db.Create(key1).Error
	require.NoError(t, err)

	key2 := &SigningKey{
		KeyID:         "unique-key",
		Algorithm:     "RS256",
		PrivateKeyPEM: "private2",
		PublicKeyPEM:  "public2",
		ActivatedAt:   time.Now(),
	}
	err = db.Create(key2).Error
	assert.Error(t, err)
}

func TestSigningKey_Expiration(t *testing.T) {
	db := setupTestDB(t)

	expiresAt := time.Now().Add(30 * 24 * time.Hour)
	key := &SigningKey{
		KeyID:         "expiring-key",
		Algorithm:     "RS256",
		PrivateKeyPEM: "private",
		PublicKeyPEM:  "public",
		IsActive:      true,
		ActivatedAt:   time.Now(),
		ExpiresAt:     &expiresAt,
	}

	err := db.Create(key).Error
	require.NoError(t, err)

	var retrieved SigningKey
	err = db.First(&retrieved, key.ID).Error
	require.NoError(t, err)

	assert.NotNil(t, retrieved.ExpiresAt)
}

// =============================================================================
// PushedAuthorizationRequest Model Tests
// =============================================================================

func TestPAR_Create(t *testing.T) {
	db := setupTestDB(t)

	app := &Application{
		Name:         "Test App",
		ClientID:     "test-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"authorization_code"},
		RedirectURIs: StringArray{"https://example.com/callback"},
	}
	err := db.Create(app).Error
	require.NoError(t, err)

	par := &PushedAuthorizationRequest{
		RequestURI:          "urn:ietf:params:oauth:request_uri:12345",
		ApplicationID:       app.ID,
		ResponseType:        "code",
		ClientID:            app.ClientID,
		RedirectURI:         "https://example.com/callback",
		Scope:               "openid profile",
		State:               "state123",
		Nonce:               "nonce123",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(90 * time.Second),
		Used:                false,
	}

	err = db.Create(par).Error
	require.NoError(t, err)

	var retrieved PushedAuthorizationRequest
	err = db.First(&retrieved, par.ID).Error
	require.NoError(t, err)

	assert.Equal(t, "urn:ietf:params:oauth:request_uri:12345", retrieved.RequestURI)
	assert.Equal(t, "code", retrieved.ResponseType)
	assert.False(t, retrieved.Used)
}

func TestPAR_UniqueRequestURI(t *testing.T) {
	db := setupTestDB(t)

	app := &Application{
		Name:         "Test App",
		ClientID:     "test-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"authorization_code"},
		RedirectURIs: StringArray{"https://example.com"},
	}
	err := db.Create(app).Error
	require.NoError(t, err)

	par1 := &PushedAuthorizationRequest{
		RequestURI:    "urn:ietf:params:oauth:request_uri:unique",
		ApplicationID: app.ID,
		ResponseType:  "code",
		ClientID:      app.ClientID,
		RedirectURI:   "https://example.com",
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	err = db.Create(par1).Error
	require.NoError(t, err)

	par2 := &PushedAuthorizationRequest{
		RequestURI:    "urn:ietf:params:oauth:request_uri:unique",
		ApplicationID: app.ID,
		ResponseType:  "code",
		ClientID:      app.ClientID,
		RedirectURI:   "https://example.com",
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	err = db.Create(par2).Error
	assert.Error(t, err)
}

// =============================================================================
// Soft Delete Tests
// =============================================================================

func TestSoftDelete_User(t *testing.T) {
	db := setupTestDB(t)

	user := &User{
		Username: "softdelete",
		Email:    "softdelete@example.com",
		Password: "password",
	}
	err := db.Create(user).Error
	require.NoError(t, err)

	// Soft delete
	err = db.Delete(user).Error
	require.NoError(t, err)

	// Should not find with normal query
	var notFound User
	err = db.First(&notFound, user.ID).Error
	assert.Error(t, err)

	// Should find with Unscoped
	var found User
	err = db.Unscoped().First(&found, user.ID).Error
	require.NoError(t, err)
	assert.NotNil(t, found.DeletedAt)
}

func TestSoftDelete_Application(t *testing.T) {
	db := setupTestDB(t)

	app := &Application{
		Name:         "Soft Delete App",
		ClientID:     "soft-delete-client",
		ClientType:   "confidential",
		GrantTypes:   StringArray{"client_credentials"},
		RedirectURIs: StringArray{"https://example.com"},
	}
	err := db.Create(app).Error
	require.NoError(t, err)

	// Soft delete
	err = db.Delete(app).Error
	require.NoError(t, err)

	// Should not find with normal query
	var notFound Application
	err = db.First(&notFound, app.ID).Error
	assert.Error(t, err)

	// Should find with Unscoped
	var found Application
	err = db.Unscoped().First(&found, app.ID).Error
	require.NoError(t, err)
	assert.NotNil(t, found.DeletedAt)
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkStringArrayScan(b *testing.B) {
	jsonData := []byte(`["one", "two", "three", "four", "five"]`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var arr StringArray
		arr.Scan(jsonData)
	}
}

func BenchmarkStringArrayValue(b *testing.B) {
	arr := StringArray{"one", "two", "three", "four", "five"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		arr.Value()
	}
}

func BenchmarkJSONBScan(b *testing.B) {
	jsonData := []byte(`{"key1": "value1", "key2": "value2", "nested": {"inner": true}}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var j JSONB
		j.Scan(jsonData)
	}
}

func BenchmarkJSONBValue(b *testing.B) {
	j := JSONB{"key1": "value1", "key2": "value2", "nested": map[string]interface{}{"inner": true}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j.Value()
	}
}
