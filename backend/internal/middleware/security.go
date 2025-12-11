package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tiiuae/oryxid/internal/logger"
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

// Logger logs HTTP requests with structured logging and request ID correlation
func Logger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip health checks
		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}

		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		// Get request ID from context (set by RequestID middleware)
		requestID, _ := c.Get("request_id")
		requestIDStr, _ := requestID.(string)

		latency := time.Since(start)
		status := c.Writer.Status()

		// Log with structured fields including request_id for correlation
		logger.Info("HTTP request",
			"request_id", requestIDStr,
			"method", c.Request.Method,
			"path", path,
			"query", query,
			"status", status,
			"latency_ms", latency.Milliseconds(),
			"client_ip", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
		)

		// Log errors separately at error level
		if len(c.Errors) > 0 {
			for _, e := range c.Errors {
				logger.Error("Request error",
					"request_id", requestIDStr,
					"error", e.Error(),
					"path", path,
				)
			}
		}
	}
}

// Recovery recovers from panics with request ID correlation
func Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		requestID, _ := c.Get("request_id")
		requestIDStr, _ := requestID.(string)

		logger.Error("Panic recovered",
			"request_id", requestIDStr,
			"error", recovered,
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
		)

		c.AbortWithStatusJSON(500, gin.H{
			"error":      "Internal Server Error",
			"request_id": requestIDStr,
		})
	})
}
