package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/logger"
	"github.com/tiiuae/oryxid/internal/oauth"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type OAuthHandler struct {
	server *oauth.Server
	db     *gorm.DB
}

func NewOAuthHandler(server *oauth.Server) *OAuthHandler {
	return &OAuthHandler{
		server: server,
		db:     server.GetDB(),
	}
}

// AuthorizeHandler handles GET /oauth/authorize
func (h *OAuthHandler) AuthorizeHandler(c *gin.Context) {
	// Check for PAR (RFC 9126) - if request_uri is present, load from stored PAR
	requestURI := c.Query("request_uri")
	clientID := c.Query("client_id")

	var req *oauth.AuthorizeRequest

	if requestURI != "" {
		// Validate and retrieve PAR
		par, err := h.server.ValidatePAR(requestURI, clientID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}

		// Populate request from PAR
		req = &oauth.AuthorizeRequest{
			ResponseType:        par.ResponseType,
			ClientID:            par.ClientID,
			RedirectURI:         par.RedirectURI,
			Scope:               par.Scope,
			State:               par.State,
			Nonce:               par.Nonce,
			CodeChallenge:       par.CodeChallenge,
			CodeChallengeMethod: par.CodeChallengeMethod,
			RequestURI:          requestURI,
		}
	} else {
		// Traditional authorization request with parameters in URL
		req = &oauth.AuthorizeRequest{
			ResponseType:        c.Query("response_type"),
			ClientID:            c.Query("client_id"),
			RedirectURI:         c.Query("redirect_uri"),
			Scope:               c.Query("scope"),
			State:               c.Query("state"),
			Nonce:               c.Query("nonce"),
			CodeChallenge:       c.Query("code_challenge"),
			CodeChallengeMethod: c.Query("code_challenge_method"),
			Audience:            c.Query("audience"),
		}
	}

	// Validate request
	app, err := h.server.ValidateAuthorizationRequest(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Log authorization attempt
	h.logAudit(c, app, "oauth.authorize", "application", app.ID.String())

	// If skip_authorization is true for the app, generate code immediately
	if app.SkipAuthorization {
		// For now, we'll assume client credentials flow (no user)
		// In a full implementation, you'd handle user sessions here
		code, err := h.server.GenerateAuthorizationCode(app, nil, req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":             "server_error",
				"error_description": "Failed to generate authorization code",
			})
			return
		}

		// Redirect with code
		redirectURL := req.RedirectURI + "?code=" + code
		if req.State != "" {
			redirectURL += "&state=" + req.State
		}
		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	// Otherwise, show authorization page
	c.HTML(http.StatusOK, "authorize.html", gin.H{
		"client_name":  app.Name,
		"client_id":    app.ClientID,
		"redirect_uri": req.RedirectURI,
		"scope":        req.Scope,
		"state":        req.State,
		"request":      req,
	})
}

// TokenHandler handles POST /oauth/token
func (h *OAuthHandler) TokenHandler(c *gin.Context) {
	var req oauth.TokenRequest

	// Parse form data
	req.GrantType = c.PostForm("grant_type")
	req.Code = c.PostForm("code")
	req.RedirectURI = c.PostForm("redirect_uri")
	req.Scope = c.PostForm("scope")
	req.Audience = c.PostForm("audience")
	req.RefreshToken = c.PostForm("refresh_token")
	req.CodeVerifier = c.PostForm("code_verifier")
	req.Username = c.PostForm("username")
	req.Password = c.PostForm("password")

	// Get client credentials - support multiple authentication methods
	var clientID, clientSecret string
	var app *database.Application
	var err error

	// Check for private_key_jwt authentication (RFC 7523)
	clientAssertion := c.PostForm("client_assertion")
	clientAssertionType := c.PostForm("client_assertion_type")

	if clientAssertion != "" && clientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		// private_key_jwt authentication
		clientID = c.PostForm("client_id")
		if clientID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "client_id required with client_assertion",
			})
			return
		}

		// Validate the JWT assertion
		tokenEndpoint := getBaseURL(c) + "/oauth/token"
		if err := h.server.ValidatePrivateKeyJWT(clientAssertion, clientID, tokenEndpoint); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_client",
				"error_description": err.Error(),
			})
			return
		}

		// Retrieve the application
		if err := h.db.Where("client_id = ?", clientID).First(&app).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid_client",
			})
			return
		}
	} else {
		// Traditional client_secret_basic or client_secret_post
		var hasAuth bool
		clientID, clientSecret, hasAuth = c.Request.BasicAuth()
		if !hasAuth {
			clientID = c.PostForm("client_id")
			clientSecret = c.PostForm("client_secret")
		}

		// Validate client
		app, err = h.validateClient(clientID, clientSecret)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_client",
				"error_description": err.Error(),
			})
			return
		}
	}

	req.ClientID = clientID
	req.ClientSecret = clientSecret

	// Validate grant type
	if req.GrantType == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unsupported_grant_type",
		})
		return
	}

	var response interface{}

	switch req.GrantType {
	case "authorization_code":
		response, err = h.server.ExchangeAuthorizationCode(&req)
	case "client_credentials":
		response, err = h.server.ClientCredentialsGrant(&req)
	case "refresh_token":
		response, err = h.server.RefreshTokenGrant(&req)
	case "password":
		response, err = h.server.PasswordGrant(&req)
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unsupported_grant_type",
		})
		return
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Log successful token generation
	h.logAudit(c, app, "oauth.token", "token", req.GrantType)

	c.JSON(http.StatusOK, response)
}

// IntrospectHandler handles POST /oauth/introspect
func (h *OAuthHandler) IntrospectHandler(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Validate client credentials
	clientID, clientSecret, hasAuth := c.Request.BasicAuth()
	if !hasAuth {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}

	// Validate client
	app, err := h.validateClient(clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_client",
		})
		return
	}

	// Introspect token
	response, err := h.server.TokenManager.IntrospectToken(token)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	// Verify the token belongs to this client or was issued by this client
	if response.ClientID != app.ClientID {
		// Check if the token was issued for an audience that includes this client
		// This is a simplified check - you might want to implement more complex logic
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}

	c.JSON(http.StatusOK, response)
}

// RevokeHandler handles POST /oauth/revoke
func (h *OAuthHandler) RevokeHandler(c *gin.Context) {
	token := c.PostForm("token")
	tokenTypeHint := c.PostForm("token_type_hint")

	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
		})
		return
	}

	// Validate client credentials
	clientID, clientSecret, hasAuth := c.Request.BasicAuth()
	if !hasAuth {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
	}

	// Validate client
	app, err := h.validateClient(clientID, clientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_client",
		})
		return
	}

	// Attempt to validate the token
	claims, err := h.server.TokenManager.ValidateToken(token)
	if err != nil {
		// Token is already invalid, return success
		c.JSON(http.StatusOK, gin.H{})
		return
	}

	// Verify the token belongs to this client
	if claims.ClientID != app.ClientID {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_client",
		})
		return
	}

	// Revoke the token
	if err := h.revokeToken(token, tokenTypeHint); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
		})
		return
	}

	// Log token revocation
	h.logAudit(c, app, "oauth.revoke", "token", tokenTypeHint)

	c.JSON(http.StatusOK, gin.H{})
}

// JWKSHandler handles GET /.well-known/jwks.json
func (h *OAuthHandler) JWKSHandler(c *gin.Context) {
	jwks, err := h.server.TokenManager.GetJWKS()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
		})
		return
	}

	c.JSON(http.StatusOK, jwks)
}

// DiscoveryHandler handles GET /.well-known/openid-configuration
func (h *OAuthHandler) DiscoveryHandler(c *gin.Context) {
	baseURL := getBaseURL(c)

	discovery := gin.H{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + "/oauth/authorize",
		"token_endpoint":                        baseURL + "/oauth/token",
		"userinfo_endpoint":                     baseURL + "/oauth/userinfo",
		"jwks_uri":                              baseURL + "/.well-known/jwks.json",
		"registration_endpoint":                 baseURL + "/oauth/register",
		"introspection_endpoint":                baseURL + "/oauth/introspect",
		"revocation_endpoint":                   baseURL + "/oauth/revoke",
		"pushed_authorization_request_endpoint": baseURL + "/oauth/par", // RFC 9126
		"require_pushed_authorization_requests": false,                  // PAR is optional (can be made required per client)
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code"}, // Only authorization code flow fully implemented
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials", "refresh_token", "password"}, // Removed implicit, added password
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "private_key_jwt"},                           // RFC 7523
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nbf", "email", "email_verified", "username", "roles"}, // Added email_verified
		"code_challenge_methods_supported":      []string{"S256"},                                                                                   // OAuth 2.1 - only S256 allowed
	}

	c.JSON(http.StatusOK, discovery)
}

// UserInfoHandler handles GET/POST /oauth/userinfo
func (h *OAuthHandler) UserInfoHandler(c *gin.Context) {
	// Get token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_token",
		})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate token
	claims, err := h.server.TokenManager.ValidateToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid_token",
		})
		return
	}

	// Check if token has openid scope
	if !strings.Contains(claims.Scope, "openid") {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "insufficient_scope",
		})
		return
	}

	// Build user info response based on requested scopes
	userInfo := gin.H{
		"sub": claims.Subject,
	}

	// Add profile information if profile scope is present
	if strings.Contains(claims.Scope, "profile") {
		userInfo["username"] = claims.Username
	}

	// Add email if email scope is present
	if strings.Contains(claims.Scope, "email") {
		userInfo["email"] = claims.Email

		// Get user from database to check email verification status
		var user database.User
		if err := h.db.Where("id = ?", claims.Subject).First(&user).Error; err == nil {
			userInfo["email_verified"] = user.EmailVerified
		} else {
			userInfo["email_verified"] = false // Default to false if user not found
		}
	}

	// Add custom claims
	if len(claims.Roles) > 0 {
		userInfo["roles"] = claims.Roles
	}

	c.JSON(http.StatusOK, userInfo)
}

// PARHandler handles POST /oauth/par (Pushed Authorization Requests - RFC 9126)
func (h *OAuthHandler) PARHandler(c *gin.Context) {
	// Extract client credentials - support multiple authentication methods
	var clientID, clientSecret string

	// Check for private_key_jwt authentication (RFC 7523)
	clientAssertion := c.PostForm("client_assertion")
	clientAssertionType := c.PostForm("client_assertion_type")

	if clientAssertion != "" && clientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		// private_key_jwt authentication
		clientID = c.PostForm("client_id")
		if clientID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "client_id required with client_assertion",
			})
			return
		}

		// Validate the JWT assertion
		tokenEndpoint := getBaseURL(c) + "/oauth/token"
		if err := h.server.ValidatePrivateKeyJWT(clientAssertion, clientID, tokenEndpoint); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":             "invalid_client",
				"error_description": err.Error(),
			})
			return
		}
	} else {
		// Traditional client_secret_basic or client_secret_post
		var hasBasicAuth bool
		clientID, clientSecret, hasBasicAuth = c.Request.BasicAuth()
		if !hasBasicAuth {
			clientID = c.PostForm("client_id")
			clientSecret = c.PostForm("client_secret")
		}

		if clientID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_client",
				"error_description": "client_id is required",
			})
			return
		}
	}

	// Build authorization request from form parameters
	req := &oauth.AuthorizeRequest{
		ResponseType:        c.PostForm("response_type"),
		ClientID:            clientID,
		RedirectURI:         c.PostForm("redirect_uri"),
		Scope:               c.PostForm("scope"),
		State:               c.PostForm("state"),
		Nonce:               c.PostForm("nonce"),
		CodeChallenge:       c.PostForm("code_challenge"),
		CodeChallengeMethod: c.PostForm("code_challenge_method"),
		Audience:            c.PostForm("audience"),
	}

	// Create PAR
	response, err := h.server.CreatePushedAuthorizationRequest(req, clientSecret)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Log PAR creation
	var app database.Application
	if err := h.db.Where("client_id = ?", clientID).First(&app).Error; err == nil {
		h.logAudit(c, &app, "oauth.par", "request_uri", response.RequestURI)
	}

	c.JSON(http.StatusCreated, response)
}

// Helper functions

func (h *OAuthHandler) validateClient(clientID, clientSecret string) (*database.Application, error) {
	var app database.Application
	if err := h.db.Where("client_id = ?", clientID).First(&app).Error; err != nil {
		return nil, err
	}

	// For public clients, don't check secret
	if app.ClientType == "public" {
		return &app, nil
	}

	// Always use bcrypt to compare hashed secret
	if err := bcrypt.CompareHashAndPassword([]byte(app.HashedClientSecret), []byte(clientSecret)); err != nil {
		return nil, err
	}

	return &app, nil
}

func (h *OAuthHandler) revokeToken(token, tokenTypeHint string) error {
	// Hash the token
	hash := sha256.Sum256([]byte(token))
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	// Update token status
	now := time.Now()
	result := h.db.Model(&database.Token{}).
		Where("token_hash = ?", tokenHash).
		Updates(map[string]interface{}{
			"revoked":    true,
			"revoked_at": now,
		})

	if result.Error != nil {
		return result.Error
	}

	// If no token was found with the hash, try to revoke refresh tokens if hint suggests it
	if result.RowsAffected == 0 && tokenTypeHint == "refresh_token" {
		// Try to find and revoke as refresh token
		result = h.db.Model(&database.Token{}).
			Where("token_hash = ? AND token_type = ?", tokenHash, "refresh").
			Updates(map[string]interface{}{
				"revoked":    true,
				"revoked_at": now,
			})
	}

	return result.Error
}

func (h *OAuthHandler) logAudit(c *gin.Context, app *database.Application, action, resource, resourceID string) {
	audit := database.AuditLog{
		ApplicationID: &app.ID,
		Action:        action,
		Resource:      resource,
		ResourceID:    resourceID,
		IPAddress:     c.ClientIP(),
		UserAgent:     c.GetHeader("User-Agent"),
		StatusCode:    c.Writer.Status(),
		Metadata: map[string]interface{}{
			"method":    c.Request.Method,
			"path":      c.Request.URL.Path,
			"client_id": app.ClientID,
		},
	}

	// Get user ID from token if available
	if auth := c.GetHeader("Authorization"); auth != "" {
		tokenString := strings.TrimPrefix(auth, "Bearer ")
		if claims, err := h.server.TokenManager.ValidateToken(tokenString); err == nil && claims.Subject != "" {
			if userID, err := uuid.Parse(claims.Subject); err == nil {
				audit.UserID = &userID
			}
		}
	}

	if err := h.db.Create(&audit).Error; err != nil {
		logger.Error("failed to create audit log", "error", err, "action", action)
	}
}

func getBaseURL(c *gin.Context) string {
	scheme := "https"
	if c.Request.TLS == nil {
		scheme = "http"
	}

	// Check for X-Forwarded headers (for reverse proxy scenarios)
	if proto := c.GetHeader("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}

	host := c.Request.Host
	if forwardedHost := c.GetHeader("X-Forwarded-Host"); forwardedHost != "" {
		host = forwardedHost
	}

	// Default to localhost for testing when host is empty
	if host == "" {
		host = "localhost"
	}

	return scheme + "://" + host
}
