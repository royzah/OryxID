package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/logger"
	"github.com/tiiuae/oryxid/internal/metrics"
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
			ResponseType:         par.ResponseType,
			ClientID:             par.ClientID,
			RedirectURI:          par.RedirectURI,
			Scope:                par.Scope,
			State:                par.State,
			Nonce:                par.Nonce,
			CodeChallenge:        par.CodeChallenge,
			CodeChallengeMethod:  par.CodeChallengeMethod,
			AuthorizationDetails: par.AuthorizationDetails, // RAR (RFC 9396)
			RequestURI:           requestURI,
		}
	} else {
		// Traditional authorization request with parameters in URL
		req = &oauth.AuthorizeRequest{
			ResponseType:         c.Query("response_type"),
			ClientID:             c.Query("client_id"),
			RedirectURI:          c.Query("redirect_uri"),
			Scope:                c.Query("scope"),
			State:                c.Query("state"),
			Nonce:                c.Query("nonce"),
			CodeChallenge:        c.Query("code_challenge"),
			CodeChallengeMethod:  c.Query("code_challenge_method"),
			Audience:             c.Query("audience"),
			AuthorizationDetails: c.Query("authorization_details"), // RAR (RFC 9396)
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
	case "urn:ietf:params:oauth:grant-type:device_code":
		// Device authorization grant (RFC 8628)
		req.DeviceCode = c.PostForm("device_code")
		if req.DeviceCode == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "device_code is required",
			})
			return
		}
		response, err = h.server.DeviceCodeGrant(&req)
		// Handle specific device code errors per RFC 8628
		if dcErr, ok := err.(*oauth.DeviceCodeError); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             dcErr.Code,
				"error_description": dcErr.Description,
			})
			return
		}
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		// Token exchange grant (RFC 8693)
		req.SubjectToken = c.PostForm("subject_token")
		req.SubjectTokenType = c.PostForm("subject_token_type")
		req.ActorToken = c.PostForm("actor_token")
		req.ActorTokenType = c.PostForm("actor_token_type")
		req.RequestedTokenType = c.PostForm("requested_token_type")
		req.Resource = c.PostForm("resource")
		response, err = h.server.TokenExchangeGrant(&req)
	case "urn:openid:params:grant-type:ciba":
		// CIBA grant (OpenID Connect CIBA)
		req.AuthReqID = c.PostForm("auth_req_id")
		if req.AuthReqID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "auth_req_id is required",
			})
			return
		}
		response, err = h.server.CIBAGrant(&req)
		// Handle specific CIBA errors
		if cibaErr, ok := err.(*oauth.CIBAError); ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             cibaErr.Code,
				"error_description": cibaErr.Description,
			})
			return
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unsupported_grant_type",
		})
		return
	}

	if err != nil {
		// Record failed authentication
		metrics.Get().RecordFailedAuth(req.GrantType)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Record successful token issuance
	metrics.Get().RecordTokenIssuance(clientID, req.GrantType)
	metrics.Get().IncrementActiveTokens()

	// Log successful token generation
	h.logAudit(c, app, "oauth.token", "token", req.GrantType)

	c.JSON(http.StatusOK, response)
}

// IntrospectHandler handles POST /oauth/introspect
func (h *OAuthHandler) IntrospectHandler(c *gin.Context) {
	start := time.Now()
	defer func() {
		metrics.Get().RecordValidationLatency(time.Since(start))
	}()

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
		metrics.Get().RecordFailedAuth("introspect_invalid_client")
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

	// Decrement active tokens
	metrics.Get().DecrementActiveTokens()

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
		"pushed_authorization_request_endpoint": baseURL + "/oauth/par",                  // RFC 9126
		"device_authorization_endpoint":         baseURL + "/oauth/device_authorization", // RFC 8628
		"backchannel_authentication_endpoint":   baseURL + "/oauth/bc-authorize",         // OpenID Connect CIBA
		"require_pushed_authorization_requests": false,                                   // PAR is optional (can be made required per client)
		// Scopes include OIDC standard scopes and TrustSky USSP integration scopes
		"scopes_supported": []string{
			"openid", "profile", "email", "offline_access",
			// TrustSky USSP scopes (dynamically created via admin API)
			"trustsky:flight:read", "trustsky:flight:write",
			"trustsky:nfz:read", "trustsky:nfz:write",
			"trustsky:telemetry:write",
			"trustsky:sky:read",
			"trustsky:operator:read", "trustsky:operator:write",
			"trustsky:admin",
		},
		"response_types_supported":                   []string{"code"}, // Only authorization code flow fully implemented
		"response_modes_supported":                   []string{"query"},
		"grant_types_supported":                      []string{"authorization_code", "client_credentials", "refresh_token", "password", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:openid:params:grant-type:ciba"},
		"backchannel_token_delivery_modes_supported": []string{"poll"}, // CIBA poll mode
		"backchannel_user_code_parameter_supported":  false,            // Not implemented yet
		"subject_types_supported":                    []string{"public"},
		"id_token_signing_alg_values_supported":      []string{"RS256"},
		"token_endpoint_auth_methods_supported":      []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}, // RFC 7523
		"claims_supported":                           []string{"sub", "iss", "aud", "exp", "iat", "nbf", "jti", "scope", "client_id", "tenant_id", "email", "email_verified", "username", "roles"},
		"code_challenge_methods_supported":           []string{"S256"}, // OAuth 2.1 - only S256 allowed
		// RAR (RFC 9396) support
		"authorization_details_types_supported":          []string{"payment_initiation", "account_information", "openid_credential"}, // Example types - extensible
		"authorization_response_iss_parameter_supported": true,                                                                       // RFC 9207
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
		ResponseType:         c.PostForm("response_type"),
		ClientID:             clientID,
		RedirectURI:          c.PostForm("redirect_uri"),
		Scope:                c.PostForm("scope"),
		State:                c.PostForm("state"),
		Nonce:                c.PostForm("nonce"),
		CodeChallenge:        c.PostForm("code_challenge"),
		CodeChallengeMethod:  c.PostForm("code_challenge_method"),
		Audience:             c.PostForm("audience"),
		AuthorizationDetails: c.PostForm("authorization_details"), // RAR (RFC 9396)
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

// DeviceAuthorizationHandler handles POST /oauth/device_authorization (RFC 8628)
func (h *OAuthHandler) DeviceAuthorizationHandler(c *gin.Context) {
	// Extract client credentials
	var clientID, clientSecret string

	// Check for private_key_jwt authentication (RFC 7523)
	clientAssertion := c.PostForm("client_assertion")
	clientAssertionType := c.PostForm("client_assertion_type")

	if clientAssertion != "" && clientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		clientID = c.PostForm("client_id")
		if clientID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": "client_id required with client_assertion",
			})
			return
		}

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

		// Validate client (for confidential clients)
		if clientID != "" && clientSecret != "" {
			if _, err := h.validateClient(clientID, clientSecret); err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":             "invalid_client",
					"error_description": err.Error(),
				})
				return
			}
		}
	}

	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "client_id is required",
		})
		return
	}

	// Build device authorization request
	req := &oauth.DeviceAuthorizationRequest{
		ClientID: clientID,
		Scope:    c.PostForm("scope"),
		Audience: c.PostForm("audience"),
	}

	// Verification URI where user will enter the code
	verificationURI := getBaseURL(c) + "/oauth/device"

	// Create device authorization
	response, err := h.server.CreateDeviceAuthorization(req, verificationURI, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Log device authorization request
	var app database.Application
	if err := h.db.Where("client_id = ?", clientID).First(&app).Error; err == nil {
		h.logAudit(c, &app, "oauth.device_authorization", "device_code", response.UserCode)
	}

	c.JSON(http.StatusOK, response)
}

// DeviceVerifyHandler handles GET /oauth/device - displays the device verification page
func (h *OAuthHandler) DeviceVerifyHandler(c *gin.Context) {
	userCode := c.Query("user_code")

	// If user_code is provided, pre-populate and show app info
	if userCode != "" {
		dc, app, err := h.server.GetDeviceCodeByUserCode(userCode)
		if err != nil {
			c.HTML(http.StatusOK, "device_verify.html", gin.H{
				"error":     err.Error(),
				"user_code": userCode,
			})
			return
		}

		c.HTML(http.StatusOK, "device_verify.html", gin.H{
			"user_code":    dc.UserCode,
			"app_name":     app.Name,
			"scope":        dc.Scope,
			"show_confirm": true,
		})
		return
	}

	// Show empty form for user to enter code
	c.HTML(http.StatusOK, "device_verify.html", gin.H{})
}

// CIBAHandler handles POST /oauth/bc-authorize (CIBA Backchannel Authentication)
func (h *OAuthHandler) CIBAHandler(c *gin.Context) {
	// Extract client credentials
	var clientID, clientSecret string
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

	// Parse requested_expiry if provided
	var requestedExpiry int
	if expiryStr := c.PostForm("requested_expiry"); expiryStr != "" {
		if exp, err := strconv.Atoi(expiryStr); err == nil {
			requestedExpiry = exp
		}
	}

	// Build CIBA request
	req := &oauth.CIBAAuthenticationRequest{
		ClientID:          clientID,
		Scope:             c.PostForm("scope"),
		ACRValues:         c.PostForm("acr_values"),
		LoginHint:         c.PostForm("login_hint"),
		LoginHintToken:    c.PostForm("login_hint_token"),
		IDTokenHint:       c.PostForm("id_token_hint"),
		BindingMessage:    c.PostForm("binding_message"),
		ClientNotifyToken: c.PostForm("client_notification_token"),
		RequestedExpiry:   requestedExpiry,
	}

	// Create CIBA authentication request
	response, err := h.server.CreateCIBAAuthentication(req, clientSecret)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Log CIBA authentication request
	var app database.Application
	if err := h.db.Where("client_id = ?", clientID).First(&app).Error; err == nil {
		h.logAudit(c, &app, "oauth.ciba_authenticate", "auth_req_id", response.AuthReqID)
	}

	c.JSON(http.StatusOK, response)
}

// DeviceAuthorizeHandler handles POST /oauth/device - processes user authorization
func (h *OAuthHandler) DeviceAuthorizeHandler(c *gin.Context) {
	userCode := c.PostForm("user_code")
	action := c.PostForm("action") // "authorize" or "deny"

	if userCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "user_code is required",
		})
		return
	}

	// Get authenticated user from session/token
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_request",
			"error_description": "user authentication required",
		})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	claims, err := h.server.TokenManager.ValidateToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "invalid or expired token",
		})
		return
	}

	// Get user from claims
	var user database.User
	if err := h.db.Where("id = ?", claims.Subject).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":             "invalid_token",
			"error_description": "user not found",
		})
		return
	}

	if action == "deny" {
		if err := h.server.DenyDeviceCode(userCode); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             "invalid_request",
				"error_description": err.Error(),
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":  "denied",
			"message": "Device authorization denied",
		})
		return
	}

	// Authorize the device
	if err := h.server.AuthorizeDeviceCode(userCode, &user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Log successful device authorization
	dc, app, _ := h.server.GetDeviceCodeByUserCode(userCode)
	if app != nil {
		h.logAudit(c, app, "oauth.device_authorized", "device_code", dc.UserCode)
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "authorized",
		"message": "Device successfully authorized",
	})
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
