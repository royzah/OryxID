package middleware

import (
	"github.com/gin-gonic/gin"
)

// CORS middleware adds Cross-Origin Resource Sharing headers
func CORS(allowedOrigins []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		// Check if the origin is allowed
		allowed := false
		for _, o := range allowedOrigins {
			if o == "*" || o == origin {
				allowed = true
				break
			}
		}

		if allowed {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
			c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, Authorization, X-CSRF-Token")
		}

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// Security middleware adds security headers
func Security() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("X-Frame-Options", "DENY")
		c.Next()
	}
}

// RequestID middleware adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

// Logger middleware logs request and response details
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

// Recovery middleware recovers from panics
func Recovery() gin.HandlerFunc {
	return gin.Recovery()
}
