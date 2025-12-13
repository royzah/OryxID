package handlers

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"image/png"
	"net/http"
	"strings"
	"time"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp/totp"
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
	Token        string       `json:"token,omitempty"`
	RefreshToken string       `json:"refresh_token,omitempty"`
	User         UserResponse `json:"user,omitempty"`
	ExpiresIn    int          `json:"expiresIn,omitempty"`
	MFARequired  bool         `json:"mfa_required,omitempty"`
	MFAToken     string       `json:"mfa_token,omitempty"`
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

	// Check if MFA is enabled
	if user.TOTPEnabled {
		// Generate a temporary MFA token
		mfaToken, err := h.tokenManager.GenerateMFAToken(&user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate MFA token"})
			return
		}

		c.JSON(http.StatusOK, LoginResponse{
			MFARequired: true,
			MFAToken:    mfaToken,
		})
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

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8"`
}

// ChangePassword handles password change for the current user
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	// Find user
	var user database.User
	if err := h.db.Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.CurrentPassword)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Current password is incorrect"})
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Update password
	if err := h.db.Model(&user).Update("password", string(hashedPassword)).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	// Log the password change
	h.logAudit(&user, nil, "user.password_change", "user", user.ID.String(), c)

	c.JSON(http.StatusOK, gin.H{"message": "Password changed successfully"})
}

// MFA Setup Response
type MFASetupResponse struct {
	Secret      string   `json:"secret"`
	QRCode      string   `json:"qr_code"` // Base64-encoded PNG image
	BackupCodes []string `json:"backup_codes"`
}

// SetupMFA generates a new TOTP secret for the user
func (h *AuthHandler) SetupMFA(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var user database.User
	if err := h.db.Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check if MFA is already enabled
	if user.TOTPEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA is already enabled"})
		return
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "OryxID",
		AccountName: user.Email,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate TOTP key"})
		return
	}

	// Generate backup codes
	backupCodes := generateBackupCodes(8)
	hashedBackupCodes := make([]string, len(backupCodes))
	for i, code := range backupCodes {
		hashed, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		hashedBackupCodes[i] = string(hashed)
	}

	// Store the secret temporarily (not enabled yet)
	if err := h.db.Model(&user).Updates(map[string]interface{}{
		"totp_secret":  key.Secret(),
		"backup_codes": database.StringArray(hashedBackupCodes),
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save TOTP secret"})
		return
	}

	// Generate QR code locally (never send secret to external services)
	qrCode, err := generateQRCode(key.URL(), 200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	c.JSON(http.StatusOK, MFASetupResponse{
		Secret:      key.Secret(),
		QRCode:      qrCode,
		BackupCodes: backupCodes,
	})
}

// generateQRCode creates a base64-encoded PNG QR code from the given content
func generateQRCode(content string, size int) (string, error) {
	// Create QR code
	qrCode, err := qr.Encode(content, qr.M, qr.Auto)
	if err != nil {
		return "", err
	}

	// Scale to desired size
	qrCode, err = barcode.Scale(qrCode, size, size)
	if err != nil {
		return "", err
	}

	// Encode as PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, qrCode); err != nil {
		return "", err
	}

	// Return as data URL
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

type VerifyMFARequest struct {
	Code string `json:"code" binding:"required"`
}

// VerifyMFA verifies the TOTP code and enables MFA
func (h *AuthHandler) VerifyMFA(c *gin.Context) {
	var req VerifyMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var user database.User
	if err := h.db.Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check if secret exists
	if user.TOTPSecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MFA setup not initiated"})
		return
	}

	// Verify the TOTP code
	valid := totp.Validate(req.Code, user.TOTPSecret)
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid verification code"})
		return
	}

	// Enable MFA
	if err := h.db.Model(&user).Update("totp_enabled", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to enable MFA"})
		return
	}

	h.logAudit(&user, nil, "user.mfa_enabled", "user", user.ID.String(), c)

	c.JSON(http.StatusOK, gin.H{"message": "MFA enabled successfully"})
}

type DisableMFARequest struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

// DisableMFA disables MFA for the user
func (h *AuthHandler) DisableMFA(c *gin.Context) {
	var req DisableMFARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var user database.User
	if err := h.db.Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid password"})
		return
	}

	// Verify TOTP code
	valid := totp.Validate(req.Code, user.TOTPSecret)
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid verification code"})
		return
	}

	// Disable MFA
	if err := h.db.Model(&user).Updates(map[string]interface{}{
		"totp_enabled": false,
		"totp_secret":  "",
		"backup_codes": database.StringArray{},
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to disable MFA"})
		return
	}

	h.logAudit(&user, nil, "user.mfa_disabled", "user", user.ID.String(), c)

	c.JSON(http.StatusOK, gin.H{"message": "MFA disabled successfully"})
}

// GetMFAStatus returns the MFA status for the current user
func (h *AuthHandler) GetMFAStatus(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var user database.User
	if err := h.db.Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"mfa_enabled": user.TOTPEnabled,
	})
}

// generateBackupCodes generates random backup codes
func generateBackupCodes(count int) []string {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		bytes := make([]byte, 5)
		rand.Read(bytes)
		codes[i] = strings.ToUpper(base32.StdEncoding.EncodeToString(bytes))[:8]
	}
	return codes
}

type VerifyMFALoginRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

// VerifyMFALogin completes login by verifying MFA code
func (h *AuthHandler) VerifyMFALogin(c *gin.Context) {
	var req VerifyMFALoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate MFA token
	userID, err := h.tokenManager.ValidateMFAToken(req.MFAToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired MFA token"})
		return
	}

	// Find user
	var user database.User
	if err := h.db.Preload("Roles").Where("id = ?", userID).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Verify TOTP code or backup code
	valid := totp.Validate(req.Code, user.TOTPSecret)
	if !valid {
		// Try backup codes
		valid = h.tryBackupCode(&user, req.Code)
	}

	if !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid verification code"})
		return
	}

	// Create admin app for token generation
	adminApp := &database.Application{
		ClientID: "admin-panel",
		Name:     "Admin Panel",
	}

	// Generate tokens
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

	refreshToken, err := h.tokenManager.GenerateRefreshToken(adminApp, &user, scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	h.logAudit(&user, nil, "user.login", "user", user.ID.String(), c)

	c.JSON(http.StatusOK, LoginResponse{
		Token:        token,
		RefreshToken: refreshToken,
		User: UserResponse{
			ID:       user.ID.String(),
			Username: user.Username,
			Email:    user.Email,
			Roles:    roles,
			IsAdmin:  user.IsAdmin,
		},
		ExpiresIn: 3600,
	})
}

// tryBackupCode tries to use a backup code and invalidates it if valid
func (h *AuthHandler) tryBackupCode(user *database.User, code string) bool {
	for i, hashedCode := range user.BackupCodes {
		if err := bcrypt.CompareHashAndPassword([]byte(hashedCode), []byte(code)); err == nil {
			// Remove used backup code
			newCodes := append(user.BackupCodes[:i], user.BackupCodes[i+1:]...)
			h.db.Model(user).Update("backup_codes", database.StringArray(newCodes))
			return true
		}
	}
	return false
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
