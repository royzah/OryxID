package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/logger"
	"github.com/tiiuae/oryxid/internal/tokens"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db           *gorm.DB
	tokenManager *tokens.TokenManager
}

func NewAuthHandler(db *gorm.DB, tm *tokens.TokenManager) *AuthHandler {
	return &AuthHandler{
		db:           db,
		tokenManager: tm,
	}
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token        string       `json:"token"`
	RefreshToken string       `json:"refresh_token"`
	User         UserResponse `json:"user"`
	ExpiresIn    int          `json:"expiresIn"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RefreshTokenResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expiresIn"`
}

type UserResponse struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	IsAdmin  bool     `json:"is_admin"`
}

// Login handles admin user login
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Find user by username or email
	var user database.User
	if err := h.db.Preload("Roles").Where("username = ? OR email = ?", req.Username, req.Username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	// Check if user is active
	if !user.IsActive {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Account is disabled"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Create a dummy application for admin panel access
	adminApp := &database.Application{
		ClientID: "admin-panel",
		Name:     "Admin Panel",
	}

	// Generate access token
	roles := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roles[i] = role.Name
	}
	scope := strings.Join(roles, " ")

	extra := map[string]interface{}{
		"is_admin": user.IsAdmin,
	}

	token, err := h.tokenManager.GenerateAccessToken(adminApp, &user, scope, "admin-panel", extra)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	// Generate refresh token
	refreshToken, err := h.tokenManager.GenerateRefreshToken(adminApp, &user, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	// Log the login
	h.logAudit(&user, nil, "user.login", "user", user.ID.String(), c)

	response := LoginResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User: UserResponse{
			ID:       user.ID.String(),
			Username: user.Username,
			Email:    user.Email,
			Roles:    roles,
			IsAdmin:  user.IsAdmin,
		},
		ExpiresIn: 3600, // 1 hour
	}

	c.JSON(http.StatusOK, response)
}

// Logout handles user logout
func (h *AuthHandler) Logout(c *gin.Context) {
	userID := c.GetString("user_id")

	// TODO:
	// 1. Revoke the token (if using a blacklist)
	// 2. Clear any server-side sessions
	// 3. Log the logout event

	// Log the logout
	var user database.User
	if err := h.db.Where("id = ?", userID).First(&user).Error; err == nil {
		h.logAudit(&user, nil, "user.logout", "user", user.ID.String(), c)
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
}

// Me returns the current user's information
func (h *AuthHandler) Me(c *gin.Context) {
	userID := c.GetString("user_id")

	var user database.User
	if err := h.db.Preload("Roles").Where("id = ?", userID).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}

	roles := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roles[i] = role.Name
	}

	response := UserResponse{
		ID:       user.ID.String(),
		Username: user.Username,
		Email:    user.Email,
		Roles:    roles,
		IsAdmin:  user.IsAdmin,
	}

	c.JSON(http.StatusOK, response)
}

// RefreshToken handles refreshing access tokens.
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate the refresh token
	claims, err := h.tokenManager.ValidateToken(req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token", "details": err.Error()})
		return
	}

	// Ensure it's a refresh token
	if claims.Type != "Refresh" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token type"})
		return
	}

	// Get user ID from claims
	userID := claims.Subject
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims: missing subject"})
		return
	}

	// Get client ID from claims
	clientID := claims.ClientID
	if clientID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims: missing client_id"})
		return
	}

	// Find user
	var user database.User
	if err := h.db.Preload("Roles").Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Check if user is active
	if !user.IsActive {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Account is disabled"})
		return
	}

	// Find application
	var app database.Application
	if err := h.db.Where("client_id = ?", clientID).First(&app).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Application not found"})
		return
	}

	// Generate new access token
	extra := map[string]interface{}{
		"is_admin": user.IsAdmin,
	}

	newAccessToken, err := h.tokenManager.GenerateAccessToken(&app, &user, claims.Scope, clientID, extra)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new token"})
		return
	}

	// Log the token refresh
	h.logAudit(&user, &app, "token.refresh", "user", user.ID.String(), c)

	c.JSON(http.StatusOK, RefreshTokenResponse{
		Token:        newAccessToken,
		RefreshToken: req.RefreshToken,
		ExpiresIn:    3600,
	})
}

// Helper function to log audit events
func (h *AuthHandler) logAudit(user *database.User, app *database.Application, action, resource, resourceID string, c *gin.Context) {
	audit := database.AuditLog{
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	}

	if user != nil {
		audit.UserID = &user.ID
	}
	if app != nil {
		audit.ApplicationID = &app.ID
	}

	if err := h.db.Create(&audit).Error; err != nil {
		// Log the error, but don't block the request
		logger.Error("failed to log audit event", "error", err, "action", action)
	}
}

// HealthHandler returns the health status of the service
func HealthHandler(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check database connection
		sqlDB, err := db.DB()
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unhealthy",
				"error":  "Database connection error",
			})
			return
		}

		if err := sqlDB.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "unhealthy",
				"error":  "Database ping failed",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"service":   "oryxid",
		})
	}
}
