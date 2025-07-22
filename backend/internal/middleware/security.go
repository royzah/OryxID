package middleware

import (
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Security adds security headers to responses
func Security() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none';")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// HSTS header (only for HTTPS)
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		c.Next()
	}
}

// RequestID adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)

		c.Next()
	}
}

// Logger logs HTTP requests
func Logger() gin.HandlerFunc {
	return gin.LoggerWithConfig(gin.LoggerConfig{
		SkipPaths: []string{"/health"},
		Formatter: func(param gin.LogFormatterParams) string {
			return param.TimeStamp.Format("2006-01-02 15:04:05") + " | " +
				param.Method + " | " +
				param.Path + " | " +
				param.Request.Proto + " | " +
				strconv.Itoa(int(param.StatusCode)) + " | " +
				param.Latency.String() + " | " +
				param.ClientIP + " | " +
				param.ErrorMessage + "\n"
		},
	})
}

// Recovery recovers from panics
func Recovery() gin.HandlerFunc {
	return gin.Recovery()
}
