package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/tokens"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Server struct {
	db           *gorm.DB
	TokenManager *tokens.TokenManager
}

type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Audience            string
	RequestURI          string // For PAR (RFC 9126)
}

type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	Scope        string
	Audience     string
	RefreshToken string
	CodeVerifier string
	Username     string
	Password     string
}

func NewServer(db *gorm.DB, tm *tokens.TokenManager) *Server {
	return &Server{
		db:           db,
		TokenManager: tm,
	}
}

// GetDB returns the database instance
func (s *Server) GetDB() *gorm.DB {
	return s.db
}

// ValidateAuthorizationRequest validates the authorization request parameters
func (s *Server) ValidateAuthorizationRequest(req *AuthorizeRequest) (*database.Application, error) {
	// Validate response type
	if req.ResponseType != "code" && req.ResponseType != "token" {
		return nil, errors.New("unsupported response type")
	}

	// Get application
	var app database.Application
	if err := s.db.Preload("Scopes").Preload("Audiences").Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client")
	}

	// Validate redirect URI
	validRedirect := false
	for _, uri := range app.RedirectURIs {
		if uri == req.RedirectURI {
			validRedirect = true
			break
		}
	}
	if !validRedirect {
		return nil, errors.New("invalid redirect URI")
	}

	// Validate scopes
	if req.Scope != "" {
		requestedScopes := strings.Split(req.Scope, " ")
		validScopes := make(map[string]bool)
		for _, scope := range app.Scopes {
			validScopes[scope.Name] = true
		}
		for _, scope := range requestedScopes {
			if !validScopes[scope] {
				return nil, fmt.Errorf("invalid scope: %s", scope)
			}
		}
	}

	// Validate PKCE for public clients
	if app.ClientType == "public" && req.CodeChallenge == "" {
		return nil, errors.New("PKCE is required for public clients")
	}

	return &app, nil
}

// GenerateAuthorizationCode creates a new authorization code
func (s *Server) GenerateAuthorizationCode(app *database.Application, user *database.User, req *AuthorizeRequest) (string, error) {
	code, err := generateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization code: %w", err)
	}

	authCode := &database.AuthorizationCode{
		Code:                code,
		ApplicationID:       app.ID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Audience:            req.Audience,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if user != nil {
		authCode.UserID = &user.ID
	}

	// Use Table() to bypass GORM model introspection issues with pq.StringArray in Application
	if err := s.db.Table("authorization_codes").Create(authCode).Error; err != nil {
		return "", err
	}

	return code, nil
}

// ExchangeAuthorizationCode exchanges an authorization code for tokens
func (s *Server) ExchangeAuthorizationCode(req *TokenRequest) (*tokens.TokenResponse, error) {
	// Validate client credentials
	var app database.Application
	if err := s.db.Preload("Scopes").Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client")
	}

	// Verify client secret
	if err := s.verifyClientSecret(&app, req.ClientSecret); err != nil {
		return nil, errors.New("invalid client credentials")
	}

	// Get authorization code
	var authCode database.AuthorizationCode
	if err := s.db.Preload("User").Where("code = ? AND application_id = ?", req.Code, app.ID).First(&authCode).Error; err != nil {
		return nil, errors.New("invalid authorization code")
	}

	// Validate code hasn't been used
	if authCode.Used {
		return nil, errors.New("authorization code already used")
	}

	// Validate code hasn't expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil, errors.New("authorization code expired")
	}

	// Validate redirect URI
	if authCode.RedirectURI != req.RedirectURI {
		return nil, errors.New("redirect URI mismatch")
	}

	// Validate PKCE if present
	if authCode.CodeChallenge != "" {
		if !validatePKCE(authCode.CodeChallenge, authCode.CodeChallengeMethod, req.CodeVerifier) {
			return nil, errors.New("invalid code verifier")
		}
	}

	// Mark code as used
	authCode.Used = true
	s.db.Save(&authCode)

	// Generate tokens
	accessToken, err := s.TokenManager.GenerateAccessToken(&app, authCode.User, authCode.Scope, authCode.Audience, nil)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.TokenManager.GenerateRefreshToken(&app, authCode.User, authCode.Scope)
	if err != nil {
		return nil, err
	}

	response := &tokens.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
	}

	// Generate ID token if openid scope is present
	if strings.Contains(authCode.Scope, "openid") && authCode.User != nil {
		idToken, err := s.TokenManager.GenerateIDToken(&app, authCode.User, authCode.Nonce, authCode.CreatedAt)
		if err != nil {
			return nil, err
		}
		response.IDToken = idToken
	}

	// Store tokens in database
	s.storeTokens(&app, authCode.User, accessToken, refreshToken)

	return response, nil
}

// ClientCredentialsGrant handles the client credentials flow
func (s *Server) ClientCredentialsGrant(req *TokenRequest) (*tokens.TokenResponse, error) {
	// Validate client credentials
	var app database.Application
	if err := s.db.Preload("Scopes").Preload("Audiences").Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client")
	}

	// Verify client secret
	if err := s.verifyClientSecret(&app, req.ClientSecret); err != nil {
		return nil, errors.New("invalid client credentials")
	}

	// Validate grant type is allowed
	grantAllowed := false
	for _, grant := range app.GrantTypes {
		if grant == "client_credentials" {
			grantAllowed = true
			break
		}
	}
	if !grantAllowed {
		return nil, errors.New("grant type not allowed for this client")
	}

	// Validate scopes
	scope := req.Scope
	if scope == "" {
		// Use default scopes
		scopes := []string{}
		for _, s := range app.Scopes {
			if s.IsDefault {
				scopes = append(scopes, s.Name)
			}
		}
		scope = strings.Join(scopes, " ")
	}

	// Generate access token
	accessToken, err := s.TokenManager.GenerateAccessToken(&app, nil, scope, req.Audience, nil)
	if err != nil {
		return nil, err
	}

	response := &tokens.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       scope,
	}

	// Store token
	s.storeTokens(&app, nil, accessToken, "")

	return response, nil
}

// RefreshTokenGrant handles the refresh token flow
func (s *Server) RefreshTokenGrant(req *TokenRequest) (*tokens.TokenResponse, error) {
	// Validate client credentials
	var app database.Application
	if err := s.db.Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client")
	}

	// Verify client secret
	if err := s.verifyClientSecret(&app, req.ClientSecret); err != nil {
		return nil, errors.New("invalid client credentials")
	}

	// Validate refresh token
	claims, err := s.TokenManager.ValidateToken(req.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Check if token type is refresh
	if claims.Type != "Refresh" {
		return nil, errors.New("token is not a refresh token")
	}

	// Check if refresh token is revoked
	hash := sha256.Sum256([]byte(req.RefreshToken))
	tokenHash := base64.URLEncoding.EncodeToString(hash[:])

	var storedToken database.Token
	if err := s.db.Where("token_hash = ? AND token_type = ?", tokenHash, "refresh").First(&storedToken).Error; err == nil {
		if storedToken.Revoked {
			return nil, errors.New("refresh token has been revoked")
		}
		if time.Now().After(storedToken.ExpiresAt) {
			return nil, errors.New("refresh token has expired")
		}
	}

	// Get user if present
	var user *database.User
	if claims.Subject != "" && claims.Subject != app.ClientID {
		user = &database.User{}
		if err := s.db.Preload("Roles").Where("id = ?", claims.Subject).First(user).Error; err != nil {
			return nil, errors.New("user not found")
		}
	}

	// Determine scope for new tokens (OAuth 2.1 scope downscaling)
	requestedScope := claims.Scope // Default to original scope
	if req.Scope != "" {
		// Client requested specific scopes - validate they're a subset of original scopes
		requestedScopes := strings.Split(req.Scope, " ")
		originalScopes := strings.Split(claims.Scope, " ")

		// Create map of original scopes for quick lookup
		originalScopeMap := make(map[string]bool)
		for _, s := range originalScopes {
			originalScopeMap[s] = true
		}

		// Validate all requested scopes were in original token
		for _, s := range requestedScopes {
			if !originalScopeMap[s] {
				return nil, errors.New("requested scope exceeds granted scope")
			}
		}

		// Use downscaled scope
		requestedScope = req.Scope
	}

	// Extract audience (if present)
	audience := ""
	if len(claims.Audience) > 0 {
		audience = claims.Audience[0]
	}

	// Generate new access token with potentially downscaled scope
	accessToken, err := s.TokenManager.GenerateAccessToken(&app, user, requestedScope, audience, nil)
	if err != nil {
		return nil, err
	}

	// Generate new refresh token with potentially downscaled scope (token rotation for security)
	newRefreshToken, err := s.TokenManager.GenerateRefreshToken(&app, user, requestedScope)
	if err != nil {
		return nil, err
	}

	// Revoke old refresh token to prevent reuse
	s.db.Model(&database.Token{}).
		Where("token_hash = ? AND token_type = ?", tokenHash, "refresh").
		Update("revoked", true)

	response := &tokens.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: newRefreshToken, // Return new refresh token (OAuth 2.1 best practice)
		Scope:        requestedScope,   // Return actual scope (might be downscaled)
	}

	// Store new access token and new refresh token
	s.storeTokens(&app, user, accessToken, newRefreshToken)

	return response, nil
}

// PasswordGrant handles the password grant flow (Resource Owner Password Credentials)
func (s *Server) PasswordGrant(req *TokenRequest) (*tokens.TokenResponse, error) {
	// Validate client credentials
	var app database.Application
	if err := s.db.Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client")
	}

	// Verify client secret
	if err := s.verifyClientSecret(&app, req.ClientSecret); err != nil {
		return nil, errors.New("invalid client credentials")
	}

	// Validate grant type is allowed
	grantAllowed := false
	for _, grant := range app.GrantTypes {
		if grant == "password" {
			grantAllowed = true
			break
		}
	}
	if !grantAllowed {
		return nil, errors.New("grant type not allowed for this client")
	}

	// Authenticate user
	var user database.User
	if err := s.db.Preload("Roles").Where("username = ? OR email = ?", req.Username, req.Username).First(&user).Error; err != nil {
		return nil, errors.New("invalid user credentials")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, errors.New("invalid user credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, errors.New("user account is disabled")
	}

	// Generate tokens
	scope := req.Scope
	if scope == "" {
		// Use default scopes
		scopes := []string{}
		var appScopes []database.Scope
		if err := s.db.Model(&app).Association("Scopes").Find(&appScopes); err == nil {
			for _, s := range appScopes {
				if s.IsDefault {
					scopes = append(scopes, s.Name)
				}
			}
		}
		scope = strings.Join(scopes, " ")
	}

	accessToken, err := s.TokenManager.GenerateAccessToken(&app, &user, scope, req.Audience, nil)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.TokenManager.GenerateRefreshToken(&app, &user, scope)
	if err != nil {
		return nil, err
	}

	response := &tokens.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        scope,
	}

	// Generate ID token if openid scope is present
	if strings.Contains(scope, "openid") {
		idToken, err := s.TokenManager.GenerateIDToken(&app, &user, "", time.Now())
		if err != nil {
			return nil, err
		}
		response.IDToken = idToken
	}

	// Store tokens
	s.storeTokens(&app, &user, accessToken, refreshToken)

	return response, nil
}

// Helper functions

func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func validatePKCE(challenge, method, verifier string) bool {
	// OAuth 2.1 only allows S256 - plain method is insecure and deprecated
	if method != "S256" {
		return false
	}

	h := sha256.Sum256([]byte(verifier))
	computed := base64.URLEncoding.EncodeToString(h[:])
	// Remove padding for comparison
	computed = strings.TrimRight(computed, "=")
	challenge = strings.TrimRight(challenge, "=")
	return computed == challenge
}

func (s *Server) verifyClientSecret(app *database.Application, providedSecret string) error {
	// For public clients, don't check secret
	if app.ClientType == "public" {
		return nil
	}

	// Always use bcrypt comparison for hashed secret
	return bcrypt.CompareHashAndPassword([]byte(app.HashedClientSecret), []byte(providedSecret))
}

func (s *Server) storeTokens(app *database.Application, user *database.User, accessToken, refreshToken string) {
	// Hash tokens before storing
	if accessToken != "" {
		h := sha256.Sum256([]byte(accessToken))
		token := &database.Token{
			TokenHash:     base64.URLEncoding.EncodeToString(h[:]),
			TokenType:     "access",
			ApplicationID: app.ID,
			ExpiresAt:     time.Now().Add(time.Hour),
		}
		if user != nil {
			token.UserID = &user.ID
		}
		// Use Table() to bypass GORM model introspection issues with pq.StringArray in Application
		s.db.Table("tokens").Create(token)
	}

	if refreshToken != "" {
		h := sha256.Sum256([]byte(refreshToken))
		token := &database.Token{
			TokenHash:     base64.URLEncoding.EncodeToString(h[:]),
			TokenType:     "refresh",
			ApplicationID: app.ID,
			ExpiresAt:     time.Now().Add(30 * 24 * time.Hour),
		}
		if user != nil {
			token.UserID = &user.ID
		}
		// Use Table() to bypass GORM model introspection issues with pq.StringArray in Application
		s.db.Table("tokens").Create(token)
	}
}

// PARResponse represents the response from a Pushed Authorization Request
type PARResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in"`
}

// CreatePushedAuthorizationRequest handles PAR (RFC 9126) - POST /oauth/par
func (s *Server) CreatePushedAuthorizationRequest(req *AuthorizeRequest, clientSecret string) (*PARResponse, error) {
	// Validate client
	var app database.Application
	if err := s.db.Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client")
	}

	// Verify client authentication (confidential clients must authenticate)
	if app.ClientType != "public" {
		if err := s.verifyClientSecret(&app, clientSecret); err != nil {
			return nil, errors.New("invalid client credentials")
		}
	}

	// Validate redirect URI
	if !slices.Contains(app.RedirectURIs, req.RedirectURI) {
		return nil, errors.New("invalid redirect URI")
	}

	// Validate response type
	if req.ResponseType != "code" {
		return nil, errors.New("unsupported response type")
	}

	// Validate PKCE if present
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "S256" {
		return nil, errors.New("only S256 code challenge method supported")
	}

	// Generate unique request URI
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	requestURIValue := base64.URLEncoding.EncodeToString(b)
	requestURI := fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", requestURIValue)

	// Store PAR with 90 second expiration (RFC 9126 recommendation)
	par := &database.PushedAuthorizationRequest{
		RequestURI:          requestURI,
		ApplicationID:       app.ID,
		ResponseType:        req.ResponseType,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(90 * time.Second),
		Used:                false,
	}

	if err := s.db.Create(par).Error; err != nil {
		return nil, fmt.Errorf("failed to store PAR: %w", err)
	}

	return &PARResponse{
		RequestURI: requestURI,
		ExpiresIn:  90,
	}, nil
}

// ValidatePAR validates and retrieves a stored PAR by request_uri
func (s *Server) ValidatePAR(requestURI, clientID string) (*database.PushedAuthorizationRequest, error) {
	var par database.PushedAuthorizationRequest

	// Find the PAR
	if err := s.db.Where("request_uri = ?", requestURI).First(&par).Error; err != nil {
		return nil, errors.New("invalid request_uri")
	}

	// Verify client ID matches
	if par.ClientID != clientID {
		return nil, errors.New("client_id mismatch")
	}

	// Check if already used (one-time use)
	if par.Used {
		return nil, errors.New("request_uri already used")
	}

	// Check if expired
	if time.Now().After(par.ExpiresAt) {
		return nil, errors.New("request_uri expired")
	}

	// Mark as used
	s.db.Model(&par).Update("used", true)

	return &par, nil
}

// ValidatePrivateKeyJWT validates a JWT used for client authentication (RFC 7523)
func (s *Server) ValidatePrivateKeyJWT(clientAssertion, clientID, tokenEndpoint string) error {
	// Find the client
	var app database.Application
	if err := s.db.Where("client_id = ?", clientID).First(&app).Error; err != nil {
		return errors.New("client not found")
	}

	// Check if client is configured for private_key_jwt
	if app.TokenEndpointAuthMethod != "private_key_jwt" {
		return errors.New("client not configured for private_key_jwt authentication")
	}

	// Client must have a public key
	if app.PublicKeyPEM == "" {
		return errors.New("client has no public key configured")
	}

	// Parse the PEM-encoded public key
	block, _ := pem.Decode([]byte(app.PublicKeyPEM))
	if block == nil {
		return errors.New("failed to parse PEM block containing the public key")
	}

	// Parse the RSA public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return errors.New("public key is not RSA")
	}

	// Parse and validate the JWT
	token, err := jwt.Parse(clientAssertion, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPub, nil
	})

	if err != nil {
		return fmt.Errorf("failed to validate JWT: %w", err)
	}

	if !token.Valid {
		return errors.New("invalid JWT")
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("invalid JWT claims")
	}

	// Validate required claims per RFC 7523
	// iss (issuer) - MUST be the client_id
	iss, ok := claims["iss"].(string)
	if !ok || iss != clientID {
		return errors.New("invalid iss claim - must equal client_id")
	}

	// sub (subject) - MUST be the client_id
	sub, ok := claims["sub"].(string)
	if !ok || sub != clientID {
		return errors.New("invalid sub claim - must equal client_id")
	}

	// aud (audience) - MUST be the token endpoint URL
	aud, ok := claims["aud"]
	if !ok {
		return errors.New("missing aud claim")
	}

	// aud can be string or array of strings
	audValid := false
	switch v := aud.(type) {
	case string:
		audValid = (v == tokenEndpoint)
	case []interface{}:
		for _, a := range v {
			if audStr, ok := a.(string); ok && audStr == tokenEndpoint {
				audValid = true
				break
			}
		}
	}

	if !audValid {
		return errors.New("invalid aud claim - must be token endpoint URL")
	}

	// exp (expiration) - MUST be present and not expired
	exp, ok := claims["exp"].(float64)
	if !ok {
		return errors.New("missing exp claim")
	}

	if time.Now().Unix() > int64(exp) {
		return errors.New("JWT expired")
	}

	// jti (JWT ID) - OPTIONAL but recommended for replay prevention
	// TODO: Implement jti replay prevention cache

	return nil
}
