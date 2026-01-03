package oryxid

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

const (
	// GinClaimsKey is the Gin context key for claims.
	GinClaimsKey = "oryxid_claims"
)

// GinMiddleware provides Gin-specific middleware.
type GinMiddleware struct {
	client *Client
}

// NewGinMiddleware creates a new Gin middleware instance.
func NewGinMiddleware(client *Client) *GinMiddleware {
	return &GinMiddleware{client: client}
}

// Protect returns Gin middleware that requires a valid token.
func (m *GinMiddleware) Protect() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ExtractToken(c.GetHeader("Authorization"))
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
			return
		}

		claims, err := m.client.ValidateJWT(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}

		c.Set(GinClaimsKey, claims)
		c.Next()
	}
}

// RequireScope returns Gin middleware that requires specific scopes.
func (m *GinMiddleware) RequireScope(required ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ExtractToken(c.GetHeader("Authorization"))
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
			return
		}

		claims, err := m.client.ValidateJWT(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}

		sc := NewScopeChecker(claims.Scope)
		if !sc.HasAll(required...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":          "insufficient_scope",
				"required_scope": required,
			})
			return
		}

		c.Set(GinClaimsKey, claims)
		c.Next()
	}
}

// RequireScopeAny returns Gin middleware that requires any of the specified scopes.
func (m *GinMiddleware) RequireScopeAny(required ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := ExtractToken(c.GetHeader("Authorization"))
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing_token"})
			return
		}

		claims, err := m.client.ValidateJWT(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid_token"})
			return
		}

		sc := NewScopeChecker(claims.Scope)
		if !sc.HasAny(required...) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":          "insufficient_scope",
				"required_scope": required,
			})
			return
		}

		c.Set(GinClaimsKey, claims)
		c.Next()
	}
}

// GetGinClaims retrieves claims from Gin context.
func GetGinClaims(c *gin.Context) *Claims {
	val, exists := c.Get(GinClaimsKey)
	if !exists {
		return nil
	}
	claims, ok := val.(*Claims)
	if !ok {
		return nil
	}
	return claims
}
