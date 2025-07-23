package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tiiuae/oryxid/internal/redis"
)

const (
	csrfTokenLength = 32
	csrfHeader      = "X-CSRF-Token"
	csrfFormField   = "csrf_token"
	csrfCookieName  = "csrf_token"
)

// CSRFConfig holds CSRF middleware configuration
type CSRFConfig struct {
	Secret         []byte
	TokenLength    int
	CookieName     string
	CookiePath     string
	CookieDomain   string
	CookieSecure   bool
	CookieHTTPOnly bool
	Header         string
	FormField      string
	ErrorHandler   gin.HandlerFunc
	SkipPaths      []string
	RedisClient    *redis.Client
}

// DefaultCSRFConfig returns default CSRF configuration
func DefaultCSRFConfig() CSRFConfig {
	return CSRFConfig{
		TokenLength:    csrfTokenLength,
		CookieName:     csrfCookieName,
		CookiePath:     "/",
		CookieSecure:   true,
		CookieHTTPOnly: true,
		Header:         csrfHeader,
		FormField:      csrfFormField,
		SkipPaths:      []string{"/health", "/metrics"},
	}
}

// CSRF creates a CSRF protection middleware
func CSRF(config CSRFConfig) gin.HandlerFunc {
	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultCSRFErrorHandler
	}

	return func(c *gin.Context) {
		// Skip CSRF check for certain paths
		for _, path := range config.SkipPaths {
			if c.Request.URL.Path == path {
				c.Next()
				return
			}
		}

		// Skip CSRF check for safe methods
		if isSafeMethod(c.Request.Method) {
			// Generate and set token for safe methods
			token := generateCSRFToken(config.TokenLength)
			setCSRFCookie(c, config, token)
			c.Set("csrf_token", token)
			c.Next()
			return
		}

		// Get token from cookie
		cookieToken, err := c.Cookie(config.CookieName)
		if err != nil || cookieToken == "" {
			config.ErrorHandler(c)
			return
		}

		// Get token from request
		requestToken := getCSRFTokenFromRequest(c, config)
		if requestToken == "" {
			config.ErrorHandler(c)
			return
		}

		// Validate tokens match
		if !validateCSRFTokens(cookieToken, requestToken) {
			config.ErrorHandler(c)
			return
		}

		// Validate token hasn't been used (if Redis is configured)
		if config.RedisClient != nil {
			if err := validateTokenNotUsed(config.RedisClient, requestToken); err != nil {
				config.ErrorHandler(c)
				return
			}
		}

		// Generate new token for next request
		newToken := generateCSRFToken(config.TokenLength)
		setCSRFCookie(c, config, newToken)
		c.Set("csrf_token", newToken)

		c.Next()
	}
}

// CSRFFromSession creates a CSRF middleware that stores tokens in session
func CSRFFromSession(sessionKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip CSRF check for safe methods
		if isSafeMethod(c.Request.Method) {
			c.Next()
			return
		}

		// Get session
		session, exists := c.Get("session")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "csrf_token_missing",
				"message": "CSRF token missing",
			})
			c.Abort()
			return
		}

		// Get token from session
		sessionData := session.(map[string]interface{})
		sessionToken, ok := sessionData[sessionKey].(string)
		if !ok || sessionToken == "" {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "csrf_token_missing",
				"message": "CSRF token missing from session",
			})
			c.Abort()
			return
		}

		// Get token from request
		requestToken := c.GetHeader(csrfHeader)
		if requestToken == "" {
			requestToken = c.PostForm(csrfFormField)
		}

		if requestToken == "" || requestToken != sessionToken {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "csrf_token_invalid",
				"message": "Invalid CSRF token",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Helper functions

func isSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
}

func generateCSRFToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
}

func setCSRFCookie(c *gin.Context, config CSRFConfig, token string) {
	c.SetCookie(
		config.CookieName,
		token,
		3600, // 1 hour
		config.CookiePath,
		config.CookieDomain,
		config.CookieSecure,
		config.CookieHTTPOnly,
	)
}

func getCSRFTokenFromRequest(c *gin.Context, config CSRFConfig) string {
	// Try header first
	token := c.GetHeader(config.Header)
	if token != "" {
		return token
	}

	// Try form field
	token = c.PostForm(config.FormField)
	if token != "" {
		return token
	}

	// Try JSON body
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err == nil {
		if val, ok := body[config.FormField].(string); ok {
			return val
		}
	}

	return ""
}

func validateCSRFTokens(cookieToken, requestToken string) bool {
	return cookieToken == requestToken && cookieToken != ""
}

func validateTokenNotUsed(client *redis.Client, token string) error {
	// Check if token has been used
	key := "csrf:used:" + token
	if err := client.GetCache(key, nil); err == nil {
		return &gin.Error{
			Err:  fmt.Errorf("CSRF token has already been used"),
			Type: gin.ErrorTypePublic,
		}
	}

	// Mark token as used (with 1 hour expiration)
	return client.SetCache(key, true, time.Hour)
}

func defaultCSRFErrorHandler(c *gin.Context) {
	c.JSON(http.StatusForbidden, gin.H{
		"error":   "csrf_token_invalid",
		"message": "Invalid or missing CSRF token",
	})
	c.Abort()
}

// CSRFToken returns a handler that provides CSRF token
func CSRFToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetString("csrf_token")
		if token == "" {
			token = generateCSRFToken(csrfTokenLength)
			c.Set("csrf_token", token)
		}

		c.JSON(http.StatusOK, gin.H{
			"csrf_token": token,
		})
	}
}

// CSRFExempt marks a route as exempt from CSRF protection
func CSRFExempt() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("csrf_exempt", true)
		c.Next()
	}
}
