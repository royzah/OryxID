package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/tokens"
	"gorm.io/gorm"
)

type AuthMiddleware struct {
	tokenManager *tokens.TokenManager
	db           *gorm.DB
}

func NewAuthMiddleware(tm *tokens.TokenManager, db *gorm.DB) *AuthMiddleware {
	return &AuthMiddleware{
		tokenManager: tm,
		db:           db,
	}
}

// RequireAuth validates JWT tokens and sets user context
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing authorization token"})
			c.Abort()
			return
		}

		// Validate token signature and expiration
		claims, err := m.tokenManager.ValidateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		// Check if token has been revoked (OAuth 2.1 security)
		hash := sha256.Sum256([]byte(token))
		tokenHash := base64.URLEncoding.EncodeToString(hash[:])

		var storedToken database.Token
		if err := m.db.Where("token_hash = ?", tokenHash).First(&storedToken).Error; err == nil {
			if storedToken.Revoked {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token has been revoked"})
				c.Abort()
				return
			}
		}

		// Set user context
		c.Set("user_id", claims.Subject)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("roles", claims.Roles)
		c.Set("client_id", claims.ClientID)
		c.Set("scope", claims.Scope)

		c.Next()
	}
}

// RequireScope checks if the token has the required scope
func (m *AuthMiddleware) RequireScope(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenScope, exists := c.Get("scope")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		scopes := strings.Split(tokenScope.(string), " ")
		for _, s := range scopes {
			if s == scope {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		c.Abort()
	}
}

// RequireRole checks if the user has the required role
func (m *AuthMiddleware) RequireRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		roles, exists := c.Get("roles")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
			c.Abort()
			return
		}

		userRoles := roles.([]string)
		for _, r := range userRoles {
			if r == role {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		c.Abort()
	}
}

// RequireAdmin checks if the user is an admin
func (m *AuthMiddleware) RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		// First check if user is authenticated
		if _, exists := c.Get("user_id"); !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		// Check for admin role
		roles, exists := c.Get("roles")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			c.Abort()
			return
		}

		userRoles := roles.([]string)
		for _, r := range userRoles {
			if r == "admin" {
				c.Next()
				return
			}
		}

		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		c.Abort()
	}
}

// OptionalAuth validates JWT tokens if present but doesn't require them
func (m *AuthMiddleware) OptionalAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := m.extractToken(c)
		if token == "" {
			c.Next()
			return
		}

		// Validate token
		claims, err := m.tokenManager.ValidateToken(token)
		if err != nil {
			// Invalid token, but since it's optional, we continue
			c.Next()
			return
		}

		// Set user context
		c.Set("user_id", claims.Subject)
		c.Set("username", claims.Username)
		c.Set("email", claims.Email)
		c.Set("roles", claims.Roles)
		c.Set("client_id", claims.ClientID)
		c.Set("scope", claims.Scope)

		c.Next()
	}
}

// extractToken extracts the JWT token from the Authorization header
func (m *AuthMiddleware) extractToken(c *gin.Context) string {
	// Check Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		// Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	// Check query parameter (for WebSocket connections)
	if token := c.Query("token"); token != "" {
		return token
	}

	// Check cookie (optional)
	if cookie, err := c.Cookie("access_token"); err == nil {
		return cookie
	}

	return ""
}
