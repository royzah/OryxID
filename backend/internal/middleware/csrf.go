package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"

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
		CookieSecure:   false, // Set to false for development; true in production
		CookieHTTPOnly: false, // IMPORTANT: Set to false so JavaScript can read it
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
		// Check if this route is marked as CSRF exempt
		if exempt, exists := c.Get("csrf_exempt"); exists && exempt.(bool) {
			c.Next()
			return
		}

		// Skip CSRF check for certain paths
		for _, path := range config.SkipPaths {
			// Support both exact match and prefix match (paths ending with *)
			if strings.HasSuffix(path, "*") {
				if strings.HasPrefix(c.Request.URL.Path, strings.TrimSuffix(path, "*")) {
					c.Next()
					return
				}
			} else if c.Request.URL.Path == path {
				c.Next()
				return
			}
		}

		// For safe methods, ensure a token exists
		if isSafeMethod(c.Request.Method) {
			// Check if token already exists in cookie
			if token, err := c.Cookie(config.CookieName); err != nil || token == "" {
				// Generate new token
				token = generateCSRFToken(config.TokenLength)
				setCSRFCookie(c, config, token)
				c.Set("csrf_token", token)
			} else {
				// Use existing token
				c.Set("csrf_token", token)
			}
			c.Next()
			return
		}

		// For unsafe methods, validate the token
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

		// Set the token in context for use by handlers
		c.Set("csrf_token", cookieToken)

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
	// Set SameSite to Lax for CSRF protection
	c.SetSameSite(http.SameSiteLaxMode)

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

	// Try JSON body (but be careful not to consume the body)
	// This is handled by binding the request to a temporary struct
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}

	// Save the current request body
	if c.Request.Body != nil {
		if err := c.ShouldBindJSON(&body); err == nil && body.CSRFToken != "" {
			return body.CSRFToken
		}
	}

	return ""
}

func validateCSRFTokens(cookieToken, requestToken string) bool {
	return cookieToken == requestToken && cookieToken != ""
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
		// Get the token from context (set by CSRF middleware)
		token, exists := c.Get("csrf_token")
		if !exists || token == "" {
			// If no token exists, check cookie
			if cookieToken, err := c.Cookie(csrfCookieName); err == nil && cookieToken != "" {
				token = cookieToken
			} else {
				// Generate new token
				token = generateCSRFToken(csrfTokenLength)
				// Set cookie with same config as CSRF middleware
				c.SetSameSite(http.SameSiteLaxMode)
				c.SetCookie(
					csrfCookieName,
					token.(string),
					3600, // 1 hour
					"/",
					"",
					false, // Not secure for development
					false, // Not HTTPOnly so JS can read it
				)
			}
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
