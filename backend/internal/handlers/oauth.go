package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tiiuae/oryxid/internal/oauth"
)

type OAuthHandler struct {
	server *oauth.Server
}

func NewOAuthHandler(server *oauth.Server) *OAuthHandler {
	return &OAuthHandler{server: server}
}

// AuthorizeHandler handles GET /oauth/authorize
func (h *OAuthHandler) AuthorizeHandler(c *gin.Context) {
	req := &oauth.AuthorizeRequest{
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

	// Validate request
	app, err := h.server.ValidateAuthorizationRequest(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

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

	// Get client credentials from Basic Auth or form
	clientID, clientSecret, hasAuth := c.Request.BasicAuth()
	if !hasAuth {
		clientID = c.PostForm("client_id")
		clientSecret = c.PostForm("client_secret")
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
	var err error

	switch req.GrantType {
	case "authorization_code":
		response, err = h.server.ExchangeAuthorizationCode(&req)
	case "client_credentials":
		response, err = h.server.ClientCredentialsGrant(&req)
	case "refresh_token":
		response, err = h.server.RefreshTokenGrant(&req)
	case "password":
		// Resource Owner Password Credentials flow - implement if needed
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unsupported_grant_type",
		})
		return
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

	// TODO: Validate client credentials
	_ = clientID
	_ = clientSecret

	// Introspect token
	response, err := h.server.TokenManager.IntrospectToken(token)
	if err != nil {
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

	// TODO: Implement token revocation
	_ = clientID
	_ = clientSecret
	_ = tokenTypeHint

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
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"},
		"response_modes_supported":              []string{"query", "fragment"},
		"grant_types_supported":                 []string{"authorization_code", "implicit", "client_credentials", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "nbf", "email", "username", "roles"},
		"code_challenge_methods_supported":      []string{"plain", "S256"},
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

	// Return user info
	userInfo := gin.H{
		"sub":      claims.Subject,
		"email":    claims.Email,
		"username": claims.Username,
		"roles":    claims.Roles,
	}

	c.JSON(http.StatusOK, userInfo)
}

func getBaseURL(c *gin.Context) string {
	scheme := "https"
	if c.Request.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + c.Request.Host
}
