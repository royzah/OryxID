package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

func setupAdminTestEnvironment(t *testing.T) (*gin.Engine, *gorm.DB, *AdminHandler, *database.User) {
	gin.SetMode(gin.TestMode)

	// Setup test database
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

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

	tm, err := tokens.NewTokenManager(jwtConfig, "http://localhost:8080")
	require.NoError(t, err)

	// Create admin handler
	adminHandler := NewAdminHandler(db, tm)

	// Setup router
	router := gin.New()

	// Create test admin user
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	adminUser := &database.User{
		Username:      "admin",
		Email:         "admin@example.com",
		EmailVerified: true,
		Password:      string(hashedPassword),
		IsActive:      true,
		IsAdmin:       true,
	}
	require.NoError(t, db.Create(adminUser).Error)

	// Middleware to set user_id in context (simulating authenticated requests)
	authMiddleware := func(userID string) gin.HandlerFunc {
		return func(c *gin.Context) {
			c.Set("user_id", userID)
			c.Next()
		}
	}

	// Register routes with auth middleware
	api := router.Group("/api/v1", authMiddleware(adminUser.ID.String()))
	{
		// Applications
		api.GET("/applications", adminHandler.ListApplications)
		api.POST("/applications", adminHandler.CreateApplication)
		api.GET("/applications/:id", adminHandler.GetApplication)
		api.PUT("/applications/:id", adminHandler.UpdateApplication)
		api.DELETE("/applications/:id", adminHandler.DeleteApplication)

		// Scopes
		api.GET("/scopes", adminHandler.ListScopes)
		api.POST("/scopes", adminHandler.CreateScope)
		api.GET("/scopes/:id", adminHandler.GetScope)
		api.PUT("/scopes/:id", adminHandler.UpdateScope)
		api.DELETE("/scopes/:id", adminHandler.DeleteScope)

		// Audiences
		api.GET("/audiences", adminHandler.ListAudiences)
		api.POST("/audiences", adminHandler.CreateAudience)
		api.GET("/audiences/:id", adminHandler.GetAudience)
		api.PUT("/audiences/:id", adminHandler.UpdateAudience)
		api.DELETE("/audiences/:id", adminHandler.DeleteAudience)

		// Users
		api.GET("/users", adminHandler.ListUsers)
		api.POST("/users", adminHandler.CreateUser)
		api.GET("/users/:id", adminHandler.GetUser)
		api.PUT("/users/:id", adminHandler.UpdateUser)
		api.DELETE("/users/:id", adminHandler.DeleteUser)

		// Audit logs
		api.GET("/audit-logs", adminHandler.ListAuditLogs)

		// Statistics
		api.GET("/stats", adminHandler.GetStatistics)
	}

	return router, db, adminHandler, adminUser
}

// =============================================================================
// Application Tests
// =============================================================================

func TestCreateApplication_Success(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	reqBody := map[string]interface{}{
		"name":          "Test App",
		"description":   "A test application",
		"client_type":   "confidential",
		"grant_types":   []string{"authorization_code", "refresh_token"},
		"redirect_uris": []string{"https://example.com/callback"},
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/applications", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Test App", response["name"])
	assert.NotEmpty(t, response["client_id"])
	assert.NotEmpty(t, response["client_secret"]) // Confidential clients get a secret
	assert.Equal(t, "confidential", response["client_type"])
}

func TestCreateApplication_PublicClient(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	reqBody := map[string]interface{}{
		"name":          "Public App",
		"client_type":   "public",
		"grant_types":   []string{"authorization_code"},
		"redirect_uris": []string{"https://example.com/callback"},
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/applications", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Public App", response["name"])
	assert.NotEmpty(t, response["client_id"])
	assert.Nil(t, response["client_secret"]) // Public clients don't get a secret
	assert.Equal(t, "public", response["client_type"])
}

func TestCreateApplication_MissingRequiredFields(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	tests := []struct {
		name    string
		reqBody map[string]interface{}
	}{
		{
			name:    "Missing name",
			reqBody: map[string]interface{}{"client_type": "confidential", "grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://example.com"}},
		},
		{
			name:    "Missing client_type",
			reqBody: map[string]interface{}{"name": "Test", "grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://example.com"}},
		},
		{
			name:    "Missing grant_types",
			reqBody: map[string]interface{}{"name": "Test", "client_type": "confidential", "redirect_uris": []string{"https://example.com"}},
		},
		{
			name:    "Missing redirect_uris",
			reqBody: map[string]interface{}{"name": "Test", "client_type": "confidential", "grant_types": []string{"authorization_code"}},
		},
		{
			name:    "Invalid client_type",
			reqBody: map[string]interface{}{"name": "Test", "client_type": "invalid", "grant_types": []string{"authorization_code"}, "redirect_uris": []string{"https://example.com"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.reqBody)
			req, _ := http.NewRequest("POST", "/api/v1/applications", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestCreateApplication_WithScopes(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	// Create some scopes first
	scope1 := &database.Scope{Name: "read", Description: "Read access"}
	scope2 := &database.Scope{Name: "write", Description: "Write access"}
	require.NoError(t, db.Create(scope1).Error)
	require.NoError(t, db.Create(scope2).Error)

	reqBody := map[string]interface{}{
		"name":          "App with Scopes",
		"client_type":   "confidential",
		"grant_types":   []string{"client_credentials"},
		"redirect_uris": []string{"https://example.com/callback"},
		"scope_ids":     []string{scope1.ID.String(), scope2.ID.String()},
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/applications", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	scopes := response["scopes"].([]interface{})
	assert.Len(t, scopes, 2)
}

func TestListApplications_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	// Create some applications
	for i := 0; i < 3; i++ {
		app := &database.Application{
			Name:         "App " + string(rune('A'+i)),
			ClientID:     "client-" + string(rune('a'+i)),
			ClientType:   "confidential",
			GrantTypes:   database.StringArray{"client_credentials"},
			RedirectURIs: database.StringArray{"https://example.com"},
		}
		require.NoError(t, db.Create(app).Error)
	}

	req, _ := http.NewRequest("GET", "/api/v1/applications", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Len(t, response, 3)
}

func TestListApplications_WithSearch(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	// Create applications with different names
	apps := []string{"Alpha App", "Beta App", "Gamma App"}
	for _, name := range apps {
		app := &database.Application{
			Name:         name,
			ClientID:     "client-" + name,
			ClientType:   "confidential",
			GrantTypes:   database.StringArray{"client_credentials"},
			RedirectURIs: database.StringArray{"https://example.com"},
		}
		require.NoError(t, db.Create(app).Error)
	}

	req, _ := http.NewRequest("GET", "/api/v1/applications?search=Alpha", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Len(t, response, 1)
	assert.Equal(t, "Alpha App", response[0]["name"])
}

func TestGetApplication_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	app := &database.Application{
		Name:         "Test App",
		ClientID:     "test-client-id",
		ClientType:   "confidential",
		GrantTypes:   database.StringArray{"client_credentials"},
		RedirectURIs: database.StringArray{"https://example.com"},
	}
	require.NoError(t, db.Create(app).Error)

	req, _ := http.NewRequest("GET", "/api/v1/applications/"+app.ID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Test App", response["name"])
	assert.Equal(t, "test-client-id", response["client_id"])
}

func TestGetApplication_NotFound(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	fakeID := uuid.New().String()
	req, _ := http.NewRequest("GET", "/api/v1/applications/"+fakeID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateApplication_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	app := &database.Application{
		Name:         "Original Name",
		ClientID:     "test-client-id",
		ClientType:   "confidential",
		GrantTypes:   database.StringArray{"client_credentials"},
		RedirectURIs: database.StringArray{"https://example.com"},
	}
	require.NoError(t, db.Create(app).Error)

	reqBody := map[string]interface{}{
		"name":        "Updated Name",
		"description": "Updated description",
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("PUT", "/api/v1/applications/"+app.ID.String(), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Updated Name", response["name"])
	assert.Equal(t, "Updated description", response["description"])
}

func TestUpdateApplication_NotFound(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	fakeID := uuid.New().String()
	reqBody := map[string]interface{}{"name": "Updated Name"}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("PUT", "/api/v1/applications/"+fakeID, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestDeleteApplication_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	app := &database.Application{
		Name:         "To Delete",
		ClientID:     "delete-me",
		ClientType:   "confidential",
		GrantTypes:   database.StringArray{"client_credentials"},
		RedirectURIs: database.StringArray{"https://example.com"},
	}
	require.NoError(t, db.Create(app).Error)

	req, _ := http.NewRequest("DELETE", "/api/v1/applications/"+app.ID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify it's deleted
	var count int64
	db.Model(&database.Application{}).Where("id = ?", app.ID).Count(&count)
	assert.Equal(t, int64(0), count)
}

func TestDeleteApplication_NotFound(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	fakeID := uuid.New().String()
	req, _ := http.NewRequest("DELETE", "/api/v1/applications/"+fakeID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// =============================================================================
// Scope Tests
// =============================================================================

func TestCreateScope_Success(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	reqBody := map[string]interface{}{
		"name":        "read:users",
		"description": "Read user data",
		"is_default":  true,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/scopes", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "read:users", response["name"])
	assert.Equal(t, "Read user data", response["description"])
	assert.Equal(t, true, response["is_default"])
}

func TestCreateScope_MissingName(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	reqBody := map[string]interface{}{
		"description": "Missing name",
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/scopes", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListScopes_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	// Create some scopes
	scopes := []string{"read", "write", "delete"}
	for _, name := range scopes {
		scope := &database.Scope{Name: name, Description: name + " permission"}
		require.NoError(t, db.Create(scope).Error)
	}

	req, _ := http.NewRequest("GET", "/api/v1/scopes", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Len(t, response, 3)
}

func TestGetScope_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	scope := &database.Scope{Name: "admin", Description: "Admin access"}
	require.NoError(t, db.Create(scope).Error)

	req, _ := http.NewRequest("GET", "/api/v1/scopes/"+scope.ID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "admin", response["name"])
}

func TestGetScope_NotFound(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	fakeID := uuid.New().String()
	req, _ := http.NewRequest("GET", "/api/v1/scopes/"+fakeID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateScope_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	scope := &database.Scope{Name: "original", Description: "Original desc"}
	require.NoError(t, db.Create(scope).Error)

	reqBody := map[string]interface{}{
		"name":        "updated",
		"description": "Updated description",
		"is_default":  true,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("PUT", "/api/v1/scopes/"+scope.ID.String(), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "updated", response["name"])
	assert.Equal(t, true, response["is_default"])
}

func TestDeleteScope_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	scope := &database.Scope{Name: "to-delete", Description: "Delete me"}
	require.NoError(t, db.Create(scope).Error)

	req, _ := http.NewRequest("DELETE", "/api/v1/scopes/"+scope.ID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

// =============================================================================
// Audience Tests
// =============================================================================

func TestCreateAudience_Success(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	reqBody := map[string]interface{}{
		"identifier":  "https://api.example.com",
		"name":        "Example API",
		"description": "Main API resource",
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/audiences", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "https://api.example.com", response["identifier"])
	assert.Equal(t, "Example API", response["name"])
}

func TestCreateAudience_WithScopes(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	// Create scopes first
	scope := &database.Scope{Name: "api:read", Description: "Read API"}
	require.NoError(t, db.Create(scope).Error)

	reqBody := map[string]interface{}{
		"identifier": "https://api.example.com",
		"name":       "API with Scopes",
		"scope_ids":  []string{scope.ID.String()},
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/audiences", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	scopes := response["scopes"].([]interface{})
	assert.Len(t, scopes, 1)
}

func TestCreateAudience_MissingFields(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	tests := []struct {
		name    string
		reqBody map[string]interface{}
	}{
		{
			name:    "Missing identifier",
			reqBody: map[string]interface{}{"name": "Test"},
		},
		{
			name:    "Missing name",
			reqBody: map[string]interface{}{"identifier": "https://api.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.reqBody)
			req, _ := http.NewRequest("POST", "/api/v1/audiences", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestListAudiences_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	// Create audiences
	for i := 0; i < 3; i++ {
		audience := &database.Audience{
			Identifier: "https://api" + string(rune('1'+i)) + ".example.com",
			Name:       "API " + string(rune('1'+i)),
		}
		require.NoError(t, db.Create(audience).Error)
	}

	req, _ := http.NewRequest("GET", "/api/v1/audiences", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Len(t, response, 3)
}

func TestGetAudience_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	audience := &database.Audience{
		Identifier: "https://api.example.com",
		Name:       "Example API",
	}
	require.NoError(t, db.Create(audience).Error)

	req, _ := http.NewRequest("GET", "/api/v1/audiences/"+audience.ID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "https://api.example.com", response["identifier"])
}

func TestGetAudience_NotFound(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	fakeID := uuid.New().String()
	req, _ := http.NewRequest("GET", "/api/v1/audiences/"+fakeID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateAudience_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	audience := &database.Audience{
		Identifier: "https://old.example.com",
		Name:       "Old Name",
	}
	require.NoError(t, db.Create(audience).Error)

	reqBody := map[string]interface{}{
		"identifier":  "https://new.example.com",
		"name":        "New Name",
		"description": "Updated audience",
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("PUT", "/api/v1/audiences/"+audience.ID.String(), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "https://new.example.com", response["identifier"])
	assert.Equal(t, "New Name", response["name"])
}

func TestDeleteAudience_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	audience := &database.Audience{
		Identifier: "https://delete.example.com",
		Name:       "Delete Me",
	}
	require.NoError(t, db.Create(audience).Error)

	req, _ := http.NewRequest("DELETE", "/api/v1/audiences/"+audience.ID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

// =============================================================================
// User Tests
// =============================================================================

func TestCreateUser_Success(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	reqBody := map[string]interface{}{
		"username":  "newuser",
		"email":     "newuser@example.com",
		"password":  "securePassword123",
		"is_active": true,
		"is_admin":  false,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/api/v1/users", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "newuser", response["username"])
	assert.Equal(t, "newuser@example.com", response["email"])
	assert.Equal(t, true, response["is_active"])
	assert.Equal(t, false, response["is_admin"])
}

func TestCreateUser_MissingFields(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	tests := []struct {
		name    string
		reqBody map[string]interface{}
	}{
		{
			name:    "Missing username",
			reqBody: map[string]interface{}{"email": "test@example.com", "password": "password123"},
		},
		{
			name:    "Missing email",
			reqBody: map[string]interface{}{"username": "test", "password": "password123"},
		},
		{
			name:    "Missing password",
			reqBody: map[string]interface{}{"username": "test", "email": "test@example.com"},
		},
		{
			name:    "Invalid email",
			reqBody: map[string]interface{}{"username": "test", "email": "invalid-email", "password": "password123"},
		},
		{
			name:    "Short password",
			reqBody: map[string]interface{}{"username": "test", "email": "test@example.com", "password": "short"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.reqBody)
			req, _ := http.NewRequest("POST", "/api/v1/users", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestListUsers_Success(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	// The setup already creates an admin user
	req, _ := http.NewRequest("GET", "/api/v1/users", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(response), 1) // At least the admin user
}

func TestListUsers_WithSearch(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	// Create additional users
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	users := []database.User{
		{Username: "alice", Email: "alice@example.com", Password: string(hashedPassword), IsActive: true},
		{Username: "bob", Email: "bob@example.com", Password: string(hashedPassword), IsActive: true},
	}
	for _, user := range users {
		db.Create(&user)
	}

	req, _ := http.NewRequest("GET", "/api/v1/users?search=alice", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response []map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Len(t, response, 1)
	assert.Equal(t, "alice", response[0]["username"])
}

func TestGetUser_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user := &database.User{
		Username: "testuser",
		Email:    "testuser@example.com",
		Password: string(hashedPassword),
		IsActive: true,
	}
	require.NoError(t, db.Create(user).Error)

	req, _ := http.NewRequest("GET", "/api/v1/users/"+user.ID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "testuser", response["username"])
	assert.Equal(t, "testuser@example.com", response["email"])
}

func TestGetUser_NotFound(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	fakeID := uuid.New().String()
	req, _ := http.NewRequest("GET", "/api/v1/users/"+fakeID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateUser_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user := &database.User{
		Username: "original",
		Email:    "original@example.com",
		Password: string(hashedPassword),
		IsActive: true,
		IsAdmin:  false,
	}
	require.NoError(t, db.Create(user).Error)

	reqBody := map[string]interface{}{
		"username":  "updated",
		"email":     "updated@example.com",
		"is_admin":  true,
		"is_active": false,
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("PUT", "/api/v1/users/"+user.ID.String(), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "updated", response["username"])
	assert.Equal(t, "updated@example.com", response["email"])
	assert.Equal(t, true, response["is_admin"])
	assert.Equal(t, false, response["is_active"])
}

func TestUpdateUser_ChangePassword(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("oldpassword"), bcrypt.DefaultCost)
	user := &database.User{
		Username: "passuser",
		Email:    "passuser@example.com",
		Password: string(hashedPassword),
		IsActive: true,
	}
	require.NoError(t, db.Create(user).Error)

	reqBody := map[string]interface{}{
		"password": "newPassword123",
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("PUT", "/api/v1/users/"+user.ID.String(), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify password was actually changed
	var updatedUser database.User
	db.First(&updatedUser, user.ID)
	err := bcrypt.CompareHashAndPassword([]byte(updatedUser.Password), []byte("newPassword123"))
	assert.NoError(t, err)
}

func TestDeleteUser_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user := &database.User{
		Username: "todelete",
		Email:    "todelete@example.com",
		Password: string(hashedPassword),
		IsActive: true,
	}
	require.NoError(t, db.Create(user).Error)

	req, _ := http.NewRequest("DELETE", "/api/v1/users/"+user.ID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}

func TestDeleteUser_CannotDeleteSelf(t *testing.T) {
	router, _, _, adminUser := setupAdminTestEnvironment(t)

	req, _ := http.NewRequest("DELETE", "/api/v1/users/"+adminUser.ID.String(), nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "Cannot delete your own account", response["error"])
}

func TestDeleteUser_NotFound(t *testing.T) {
	router, _, _, _ := setupAdminTestEnvironment(t)

	fakeID := uuid.New().String()
	req, _ := http.NewRequest("DELETE", "/api/v1/users/"+fakeID, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// =============================================================================
// Audit Log Tests
// =============================================================================

func TestListAuditLogs_Success(t *testing.T) {
	router, db, _, adminUser := setupAdminTestEnvironment(t)

	// Create some audit logs
	for i := 0; i < 5; i++ {
		log := &database.AuditLog{
			UserID:     &adminUser.ID,
			Action:     "test.action",
			Resource:   "test",
			ResourceID: uuid.New().String(),
			StatusCode: 200,
		}
		require.NoError(t, db.Create(log).Error)
	}

	req, _ := http.NewRequest("GET", "/api/v1/audit-logs", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	logs := response["logs"].([]interface{})
	assert.GreaterOrEqual(t, len(logs), 5)
	assert.NotNil(t, response["total"])
	assert.NotNil(t, response["page"])
	assert.NotNil(t, response["limit"])
}

func TestListAuditLogs_WithPagination(t *testing.T) {
	router, db, _, adminUser := setupAdminTestEnvironment(t)

	// Create audit logs
	for i := 0; i < 10; i++ {
		log := &database.AuditLog{
			UserID:     &adminUser.ID,
			Action:     "test.action",
			Resource:   "test",
			ResourceID: uuid.New().String(),
			StatusCode: 200,
		}
		require.NoError(t, db.Create(log).Error)
	}

	req, _ := http.NewRequest("GET", "/api/v1/audit-logs?page=1&limit=5", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	logs := response["logs"].([]interface{})
	assert.Len(t, logs, 5)
	assert.Equal(t, float64(1), response["page"])
	assert.Equal(t, float64(5), response["limit"])
}

func TestListAuditLogs_WithFilters(t *testing.T) {
	router, db, _, adminUser := setupAdminTestEnvironment(t)

	// Create audit logs with different actions
	actions := []string{"user.create", "user.update", "app.create"}
	for _, action := range actions {
		log := &database.AuditLog{
			UserID:     &adminUser.ID,
			Action:     action,
			Resource:   "test",
			ResourceID: uuid.New().String(),
			StatusCode: 200,
		}
		require.NoError(t, db.Create(log).Error)
	}

	req, _ := http.NewRequest("GET", "/api/v1/audit-logs?action=user.create", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	logs := response["logs"].([]interface{})
	assert.Len(t, logs, 1)
}

// =============================================================================
// Statistics Tests
// =============================================================================

func TestGetStatistics_Success(t *testing.T) {
	router, db, _, _ := setupAdminTestEnvironment(t)

	// Create some data
	app := &database.Application{
		Name:         "Stats App",
		ClientID:     "stats-client",
		ClientType:   "confidential",
		GrantTypes:   database.StringArray{"client_credentials"},
		RedirectURIs: database.StringArray{"https://example.com"},
	}
	require.NoError(t, db.Create(app).Error)

	scope := &database.Scope{Name: "stats:read"}
	require.NoError(t, db.Create(scope).Error)

	audience := &database.Audience{Identifier: "https://stats.api", Name: "Stats API"}
	require.NoError(t, db.Create(audience).Error)

	req, _ := http.NewRequest("GET", "/api/v1/stats", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.GreaterOrEqual(t, response["applications"].(float64), float64(1))
	assert.GreaterOrEqual(t, response["users"].(float64), float64(1))
	assert.GreaterOrEqual(t, response["scopes"].(float64), float64(1))
	assert.GreaterOrEqual(t, response["audiences"].(float64), float64(1))
	assert.NotNil(t, response["active_tokens"])
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkListApplications(b *testing.B) {
	router, db, _, _ := setupAdminTestEnvironment(&testing.T{})

	// Create some applications
	for i := 0; i < 100; i++ {
		app := &database.Application{
			Name:         "App " + string(rune(i)),
			ClientID:     "client-" + string(rune(i)),
			ClientType:   "confidential",
			GrantTypes:   database.StringArray{"client_credentials"},
			RedirectURIs: database.StringArray{"https://example.com"},
		}
		db.Create(app)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/api/v1/applications", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkCreateApplication(b *testing.B) {
	router, _, _, _ := setupAdminTestEnvironment(&testing.T{})

	reqBody := map[string]interface{}{
		"name":          "Benchmark App",
		"client_type":   "confidential",
		"grant_types":   []string{"client_credentials"},
		"redirect_uris": []string{"https://example.com"},
	}
	body, _ := json.Marshal(reqBody)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "/api/v1/applications", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

func BenchmarkGetStatistics(b *testing.B) {
	router, _, _, _ := setupAdminTestEnvironment(&testing.T{})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/api/v1/stats", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}
