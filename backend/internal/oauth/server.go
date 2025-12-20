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
	ResponseType         string
	ClientID             string
	RedirectURI          string
	Scope                string
	State                string
	Nonce                string
	CodeChallenge        string
	CodeChallengeMethod  string
	Audience             string
	RequestURI           string // For PAR (RFC 9126)
	AuthorizationDetails string // For RAR (RFC 9396) - JSON array of authorization details
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
	DeviceCode   string // For device authorization grant (RFC 8628)
	// Token Exchange (RFC 8693) parameters
	SubjectToken       string // The token being exchanged
	SubjectTokenType   string // urn:ietf:params:oauth:token-type:access_token, etc.
	ActorToken         string // Optional actor token for delegation
	ActorTokenType     string // Type of actor token
	RequestedTokenType string // Type of token to return
	Resource           string // Target resource/API
	// CIBA parameters
	AuthReqID string // For CIBA grant type
}

// DeviceAuthorizationRequest represents a device authorization request (RFC 8628)
type DeviceAuthorizationRequest struct {
	ClientID string
	Scope    string
	Audience string
}

// DeviceAuthorizationResponse represents the response from device authorization (RFC 8628)
type DeviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Token type URNs for RFC 8693 Token Exchange
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
)

// TokenExchangeResponse represents the response from token exchange (RFC 8693)
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in,omitempty"`
	Scope           string `json:"scope,omitempty"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

// CIBAAuthenticationRequest represents a CIBA backchannel authentication request
type CIBAAuthenticationRequest struct {
	ClientID          string
	Scope             string
	ACRValues         string
	LoginHint         string
	LoginHintToken    string
	IDTokenHint       string
	BindingMessage    string
	ClientNotifyToken string
	RequestedExpiry   int
}

// CIBAAuthenticationResponse represents the response from CIBA authentication initiation
type CIBAAuthenticationResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval,omitempty"`
}

// CIBAError represents an error during CIBA flow
type CIBAError struct {
	Code        string
	Description string
}

func (e *CIBAError) Error() string {
	return e.Description
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
		Code:                 code,
		ApplicationID:        app.ID,
		RedirectURI:          req.RedirectURI,
		Scope:                req.Scope,
		Audience:             req.Audience,
		AuthorizationDetails: req.AuthorizationDetails, // RAR (RFC 9396)
		State:                req.State,
		Nonce:                req.Nonce,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		ExpiresAt:            time.Now().Add(10 * time.Minute),
	}

	if user != nil {
		authCode.UserID = &user.ID
	}

	// Use Table() to bypass GORM model introspection issues with pq.StringArray in Application
	if err := s.db.Create(authCode).Error; err != nil {
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
		AccessToken:          accessToken,
		TokenType:            "Bearer",
		ExpiresIn:            3600,
		RefreshToken:         refreshToken,
		Scope:                authCode.Scope,
		AuthorizationDetails: authCode.AuthorizationDetails, // RAR (RFC 9396)
	}

	// Generate ID token if openid scope is present
	if strings.Contains(authCode.Scope, "openid") && authCode.User != nil {
		idToken, err := s.TokenManager.GenerateIDToken(&app, authCode.User, authCode.Nonce, authCode.CreatedAt)
		if err != nil {
			return nil, err
		}
		response.IDToken = idToken
	}

	// Store tokens in database with authorization_details
	s.storeTokensWithAuthDetails(&app, authCode.User, accessToken, refreshToken, authCode.AuthorizationDetails)

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

	// Build map of allowed scopes for this client
	allowedScopes := make(map[string]bool)
	for _, s := range app.Scopes {
		allowedScopes[s.Name] = true
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
	} else {
		// Validate that requested scopes are allowed for this client
		requestedScopes := strings.Split(scope, " ")
		for _, s := range requestedScopes {
			if !allowedScopes[s] {
				return nil, fmt.Errorf("scope '%s' is not allowed for this client", s)
			}
		}
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
		Scope:        requestedScope,  // Return actual scope (might be downscaled)
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

	// Load scopes for the application
	var appScopes []database.Scope
	s.db.Model(&app).Association("Scopes").Find(&appScopes)

	// Build map of allowed scopes for this client
	allowedScopes := make(map[string]bool)
	for _, sc := range appScopes {
		allowedScopes[sc.Name] = true
	}

	// Generate tokens
	scope := req.Scope
	if scope == "" {
		// Use default scopes
		scopes := []string{}
		for _, sc := range appScopes {
			if sc.IsDefault {
				scopes = append(scopes, sc.Name)
			}
		}
		scope = strings.Join(scopes, " ")
	} else {
		// Validate that requested scopes are allowed for this client
		requestedScopes := strings.Split(scope, " ")
		for _, sc := range requestedScopes {
			if !allowedScopes[sc] {
				return nil, fmt.Errorf("scope '%s' is not allowed for this client", sc)
			}
		}
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
	s.storeTokensWithAuthDetails(app, user, accessToken, refreshToken, "")
}

// storeTokensWithAuthDetails stores tokens with optional authorization_details (RAR - RFC 9396)
func (s *Server) storeTokensWithAuthDetails(app *database.Application, user *database.User, accessToken, refreshToken, authorizationDetails string) {
	// Hash tokens before storing
	if accessToken != "" {
		h := sha256.Sum256([]byte(accessToken))
		token := &database.Token{
			TokenHash:            base64.URLEncoding.EncodeToString(h[:]),
			TokenType:            "access",
			ApplicationID:        app.ID,
			ExpiresAt:            time.Now().Add(time.Hour),
			AuthorizationDetails: authorizationDetails,
		}
		if user != nil {
			token.UserID = &user.ID
		}
		// Use Table() to bypass GORM model introspection issues with pq.StringArray in Application
		s.db.Create(token)
	}

	if refreshToken != "" {
		h := sha256.Sum256([]byte(refreshToken))
		token := &database.Token{
			TokenHash:            base64.URLEncoding.EncodeToString(h[:]),
			TokenType:            "refresh",
			ApplicationID:        app.ID,
			ExpiresAt:            time.Now().Add(30 * 24 * time.Hour),
			AuthorizationDetails: authorizationDetails,
		}
		if user != nil {
			token.UserID = &user.ID
		}
		// Use Table() to bypass GORM model introspection issues with pq.StringArray in Application
		s.db.Create(token)
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
		RequestURI:           requestURI,
		ApplicationID:        app.ID,
		ResponseType:         req.ResponseType,
		ClientID:             req.ClientID,
		RedirectURI:          req.RedirectURI,
		Scope:                req.Scope,
		State:                req.State,
		Nonce:                req.Nonce,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		AuthorizationDetails: req.AuthorizationDetails, // RAR (RFC 9396)
		ExpiresAt:            time.Now().Add(90 * time.Second),
		Used:                 false,
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

// CreateDeviceAuthorization creates a new device authorization request (RFC 8628)
func (s *Server) CreateDeviceAuthorization(req *DeviceAuthorizationRequest, verificationURI, clientIP string) (*DeviceAuthorizationResponse, error) {
	// Validate client
	var app database.Application
	if err := s.db.Preload("Scopes").Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client")
	}

	// Validate grant type is allowed for this client
	grantAllowed := false
	for _, grant := range app.GrantTypes {
		if grant == "urn:ietf:params:oauth:grant-type:device_code" {
			grantAllowed = true
			break
		}
	}
	if !grantAllowed {
		return nil, errors.New("device_code grant type not allowed for this client")
	}

	// Validate scopes if provided
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
	} else {
		// Validate requested scopes
		requestedScopes := strings.Split(scope, " ")
		validScopes := make(map[string]bool)
		for _, s := range app.Scopes {
			validScopes[s.Name] = true
		}
		for _, s := range requestedScopes {
			if !validScopes[s] {
				return nil, fmt.Errorf("invalid scope: %s", s)
			}
		}
	}

	// Generate device code (32 bytes = 256 bits of entropy)
	deviceCode, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate device code: %w", err)
	}

	// Generate user-friendly code (8 characters, easy to type)
	userCode, err := generateUserCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate user code: %w", err)
	}

	// RFC 8628 recommends expiration between 10-30 minutes
	expiresIn := 1800 // 30 minutes
	interval := 5     // 5 seconds between polls

	// Store device code
	dc := &database.DeviceCode{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		ApplicationID:   app.ID,
		Scope:           scope,
		Audience:        req.Audience,
		VerificationURI: verificationURI,
		ExpiresAt:       time.Now().Add(time.Duration(expiresIn) * time.Second),
		Interval:        interval,
		Status:          "pending",
		ClientIP:        clientIP,
	}

	if err := s.db.Create(dc).Error; err != nil {
		return nil, fmt.Errorf("failed to store device code: %w", err)
	}

	return &DeviceAuthorizationResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURI + "?user_code=" + userCode,
		ExpiresIn:               expiresIn,
		Interval:                interval,
	}, nil
}

// DeviceCodeGrant handles the device code grant flow (RFC 8628)
func (s *Server) DeviceCodeGrant(req *TokenRequest) (*tokens.TokenResponse, error) {
	// Validate client credentials
	var app database.Application
	if err := s.db.Preload("Scopes").Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client")
	}

	// Verify client secret (for confidential clients)
	if err := s.verifyClientSecret(&app, req.ClientSecret); err != nil {
		return nil, errors.New("invalid client credentials")
	}

	// Find device code
	var dc database.DeviceCode
	if err := s.db.Preload("User").Where("device_code = ? AND application_id = ?", req.DeviceCode, app.ID).First(&dc).Error; err != nil {
		return nil, errors.New("invalid device code")
	}

	// Check expiration
	if time.Now().After(dc.ExpiresAt) {
		// Mark as expired
		s.db.Model(&dc).Update("status", "expired")
		return nil, &DeviceCodeError{Code: "expired_token", Description: "device code has expired"}
	}

	// Check polling rate (slow_down error per RFC 8628)
	if dc.LastPollAt != nil {
		timeSinceLastPoll := time.Since(*dc.LastPollAt)
		if timeSinceLastPoll < time.Duration(dc.Interval)*time.Second {
			return nil, &DeviceCodeError{Code: "slow_down", Description: "polling too frequently"}
		}
	}

	// Update last poll time
	now := time.Now()
	s.db.Model(&dc).Update("last_poll_at", now)

	// Check status
	switch dc.Status {
	case "pending":
		return nil, &DeviceCodeError{Code: "authorization_pending", Description: "user has not yet authorized"}
	case "denied":
		return nil, &DeviceCodeError{Code: "access_denied", Description: "user denied the authorization request"}
	case "authorized":
		// Continue to token generation
	default:
		return nil, errors.New("invalid device code status")
	}

	// Get the authorized user
	var user *database.User
	if dc.UserID != nil {
		user = &database.User{}
		if err := s.db.Preload("Roles").Where("id = ?", dc.UserID).First(user).Error; err != nil {
			return nil, errors.New("user not found")
		}
	}

	// Generate tokens
	accessToken, err := s.TokenManager.GenerateAccessToken(&app, user, dc.Scope, dc.Audience, nil)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.TokenManager.GenerateRefreshToken(&app, user, dc.Scope)
	if err != nil {
		return nil, err
	}

	response := &tokens.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        dc.Scope,
	}

	// Generate ID token if openid scope is present
	if strings.Contains(dc.Scope, "openid") && user != nil {
		idToken, err := s.TokenManager.GenerateIDToken(&app, user, "", *dc.AuthorizedAt)
		if err != nil {
			return nil, err
		}
		response.IDToken = idToken
	}

	// Store tokens
	s.storeTokens(&app, user, accessToken, refreshToken)

	// Mark device code as used (delete or mark consumed)
	s.db.Delete(&dc)

	return response, nil
}

// AuthorizeDeviceCode authorizes a device code with the given user
func (s *Server) AuthorizeDeviceCode(userCode string, user *database.User) error {
	var dc database.DeviceCode
	if err := s.db.Where("user_code = ?", strings.ToUpper(userCode)).First(&dc).Error; err != nil {
		return errors.New("invalid user code")
	}

	// Check expiration
	if time.Now().After(dc.ExpiresAt) {
		s.db.Model(&dc).Update("status", "expired")
		return errors.New("device code has expired")
	}

	// Check if already authorized
	if dc.Status != "pending" {
		return errors.New("device code already processed")
	}

	// Authorize the device code
	now := time.Now()
	updates := map[string]interface{}{
		"status":        "authorized",
		"user_id":       user.ID,
		"authorized_at": now,
	}

	if err := s.db.Model(&dc).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to authorize device code: %w", err)
	}

	return nil
}

// DenyDeviceCode denies a device code authorization
func (s *Server) DenyDeviceCode(userCode string) error {
	var dc database.DeviceCode
	if err := s.db.Where("user_code = ?", strings.ToUpper(userCode)).First(&dc).Error; err != nil {
		return errors.New("invalid user code")
	}

	// Check expiration
	if time.Now().After(dc.ExpiresAt) {
		s.db.Model(&dc).Update("status", "expired")
		return errors.New("device code has expired")
	}

	// Check if already processed
	if dc.Status != "pending" {
		return errors.New("device code already processed")
	}

	// Deny the device code
	if err := s.db.Model(&dc).Update("status", "denied").Error; err != nil {
		return fmt.Errorf("failed to deny device code: %w", err)
	}

	return nil
}

// GetDeviceCodeByUserCode retrieves device code info by user code (for verification UI)
func (s *Server) GetDeviceCodeByUserCode(userCode string) (*database.DeviceCode, *database.Application, error) {
	var dc database.DeviceCode
	if err := s.db.Where("user_code = ?", strings.ToUpper(userCode)).First(&dc).Error; err != nil {
		return nil, nil, errors.New("invalid user code")
	}

	// Check expiration
	if time.Now().After(dc.ExpiresAt) {
		s.db.Model(&dc).Update("status", "expired")
		return nil, nil, errors.New("device code has expired")
	}

	// Check if already processed
	if dc.Status != "pending" {
		return nil, nil, errors.New("device code already processed")
	}

	// Get application
	var app database.Application
	if err := s.db.Where("id = ?", dc.ApplicationID).First(&app).Error; err != nil {
		return nil, nil, errors.New("application not found")
	}

	return &dc, &app, nil
}

// DeviceCodeError represents an error during device code flow (RFC 8628)
type DeviceCodeError struct {
	Code        string
	Description string
}

func (e *DeviceCodeError) Error() string {
	return e.Description
}

// generateUserCode generates a user-friendly code for device authorization
// Format: XXXX-XXXX where X is an uppercase letter (excluding ambiguous characters)
func generateUserCode() (string, error) {
	// Characters that are easy to distinguish (no O, 0, I, 1, L, etc.)
	charset := "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	code := make([]byte, 8)

	for i := range code {
		b := make([]byte, 1)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		code[i] = charset[int(b[0])%len(charset)]
	}

	// Format as XXXX-XXXX
	return string(code[:4]) + "-" + string(code[4:]), nil
}

// TokenExchangeGrant handles the token exchange flow (RFC 8693)
// This allows exchanging one token for another for delegation, impersonation, or cross-domain scenarios
func (s *Server) TokenExchangeGrant(req *TokenRequest) (*TokenExchangeResponse, error) {
	// Validate client credentials
	var app database.Application
	if err := s.db.Preload("Scopes").Preload("Audiences").Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client")
	}

	// Verify client secret
	if err := s.verifyClientSecret(&app, req.ClientSecret); err != nil {
		return nil, errors.New("invalid client credentials")
	}

	// Validate grant type is allowed for this client
	grantAllowed := false
	for _, grant := range app.GrantTypes {
		if grant == "urn:ietf:params:oauth:grant-type:token-exchange" {
			grantAllowed = true
			break
		}
	}
	if !grantAllowed {
		return nil, errors.New("token exchange grant type not allowed for this client")
	}

	// Validate required parameters
	if req.SubjectToken == "" {
		return nil, errors.New("subject_token is required")
	}
	if req.SubjectTokenType == "" {
		return nil, errors.New("subject_token_type is required")
	}

	// Validate subject_token_type
	validTokenTypes := map[string]bool{
		TokenTypeAccessToken:  true,
		TokenTypeRefreshToken: true,
		TokenTypeIDToken:      true,
		TokenTypeJWT:          true,
	}
	if !validTokenTypes[req.SubjectTokenType] {
		return nil, errors.New("invalid subject_token_type")
	}

	// Validate the subject token
	subjectClaims, err := s.TokenManager.ValidateToken(req.SubjectToken)
	if err != nil {
		return nil, errors.New("invalid subject_token")
	}

	// Check if the subject token is revoked
	subjectHash := sha256.Sum256([]byte(req.SubjectToken))
	subjectTokenHash := base64.URLEncoding.EncodeToString(subjectHash[:])
	var storedToken database.Token
	if err := s.db.Where("token_hash = ?", subjectTokenHash).First(&storedToken).Error; err == nil {
		if storedToken.Revoked {
			return nil, errors.New("subject_token has been revoked")
		}
	}

	// If actor_token is provided, validate it (for delegation scenarios)
	var actorClaims *tokens.CustomClaims
	if req.ActorToken != "" {
		if req.ActorTokenType == "" {
			return nil, errors.New("actor_token_type is required when actor_token is provided")
		}
		if !validTokenTypes[req.ActorTokenType] {
			return nil, errors.New("invalid actor_token_type")
		}
		actorClaims, err = s.TokenManager.ValidateToken(req.ActorToken)
		if err != nil {
			return nil, errors.New("invalid actor_token")
		}
	}

	// Determine the requested token type (default to access token)
	requestedType := req.RequestedTokenType
	if requestedType == "" {
		requestedType = TokenTypeAccessToken
	}

	// Determine scope - use requested scope if provided, otherwise use subject token's scope
	scope := req.Scope
	if scope == "" {
		scope = subjectClaims.Scope
	} else {
		// Validate that requested scopes are a subset of subject token's scopes
		requestedScopes := strings.Split(scope, " ")
		originalScopes := strings.Split(subjectClaims.Scope, " ")
		originalScopeMap := make(map[string]bool)
		for _, s := range originalScopes {
			originalScopeMap[s] = true
		}
		for _, s := range requestedScopes {
			if !originalScopeMap[s] {
				return nil, errors.New("requested scope exceeds subject token scope")
			}
		}
	}

	// Determine audience - use requested audience/resource, or original token's audience
	audience := req.Audience
	if audience == "" {
		audience = req.Resource
	}
	if audience == "" && len(subjectClaims.Audience) > 0 {
		audience = subjectClaims.Audience[0]
	}

	// Get the user from the subject token (if present)
	var user *database.User
	if subjectClaims.Subject != "" && subjectClaims.Subject != app.ClientID {
		user = &database.User{}
		if err := s.db.Preload("Roles").Where("id = ?", subjectClaims.Subject).First(user).Error; err != nil {
			// Subject might not be a user ID (could be a service account), continue without user
			user = nil
		}
	}

	// Build extra claims for delegation (if actor token provided)
	var extraClaims map[string]interface{}
	if actorClaims != nil {
		extraClaims = map[string]interface{}{
			"act": map[string]interface{}{
				"sub":       actorClaims.Subject,
				"client_id": actorClaims.ClientID,
			},
		}
	}

	// Generate the new token based on requested type
	var response *TokenExchangeResponse

	switch requestedType {
	case TokenTypeAccessToken, TokenTypeJWT:
		accessToken, err := s.TokenManager.GenerateAccessToken(&app, user, scope, audience, extraClaims)
		if err != nil {
			return nil, err
		}
		response = &TokenExchangeResponse{
			AccessToken:     accessToken,
			IssuedTokenType: TokenTypeAccessToken,
			TokenType:       "Bearer",
			ExpiresIn:       3600,
			Scope:           scope,
		}
		// Store the new access token
		s.storeTokens(&app, user, accessToken, "")

	case TokenTypeRefreshToken:
		refreshToken, err := s.TokenManager.GenerateRefreshToken(&app, user, scope)
		if err != nil {
			return nil, err
		}
		response = &TokenExchangeResponse{
			AccessToken:     refreshToken, // RefreshToken goes in access_token field per spec
			IssuedTokenType: TokenTypeRefreshToken,
			TokenType:       "N_A", // Per RFC 8693, token_type is "N_A" for non-access tokens
			Scope:           scope,
		}
		// Store the new refresh token
		s.storeTokens(&app, user, "", refreshToken)

	case TokenTypeIDToken:
		if user == nil {
			return nil, errors.New("cannot issue ID token without user context")
		}
		idToken, err := s.TokenManager.GenerateIDToken(&app, user, "", time.Now())
		if err != nil {
			return nil, err
		}
		response = &TokenExchangeResponse{
			AccessToken:     idToken, // ID token goes in access_token field per spec
			IssuedTokenType: TokenTypeIDToken,
			TokenType:       "N_A",
		}

	default:
		return nil, errors.New("unsupported requested_token_type")
	}

	return response, nil
}

// CreateCIBAAuthentication creates a new CIBA authentication request (OpenID Connect CIBA)
func (s *Server) CreateCIBAAuthentication(req *CIBAAuthenticationRequest, clientSecret string) (*CIBAAuthenticationResponse, error) {
	// Validate client
	var app database.Application
	if err := s.db.Preload("Scopes").Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client")
	}

	// Verify client secret (CIBA requires confidential clients)
	if err := s.verifyClientSecret(&app, clientSecret); err != nil {
		return nil, errors.New("invalid client credentials")
	}

	// Validate grant type is allowed for this client
	grantAllowed := false
	for _, grant := range app.GrantTypes {
		if grant == "urn:openid:params:grant-type:ciba" {
			grantAllowed = true
			break
		}
	}
	if !grantAllowed {
		return nil, errors.New("CIBA grant type not allowed for this client")
	}

	// At least one hint is required to identify the user
	if req.LoginHint == "" && req.LoginHintToken == "" && req.IDTokenHint == "" {
		return nil, errors.New("one of login_hint, login_hint_token, or id_token_hint is required")
	}

	// Find the user based on the hint
	var user *database.User
	if req.LoginHint != "" {
		user = &database.User{}
		// Login hint can be username or email
		if err := s.db.Where("username = ? OR email = ?", req.LoginHint, req.LoginHint).First(user).Error; err != nil {
			return nil, errors.New("user not found")
		}
	} else if req.IDTokenHint != "" {
		// Validate the ID token and extract user
		claims, err := s.TokenManager.ValidateToken(req.IDTokenHint)
		if err != nil {
			return nil, errors.New("invalid id_token_hint")
		}
		user = &database.User{}
		if err := s.db.Where("id = ?", claims.Subject).First(user).Error; err != nil {
			return nil, errors.New("user from id_token_hint not found")
		}
	}
	// Note: login_hint_token would require parsing a JWT containing the hint

	if user == nil {
		return nil, errors.New("unable to identify user from hints")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, errors.New("user account is disabled")
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
	} else {
		// Validate requested scopes
		requestedScopes := strings.Split(scope, " ")
		validScopes := make(map[string]bool)
		for _, s := range app.Scopes {
			validScopes[s.Name] = true
		}
		for _, s := range requestedScopes {
			if !validScopes[s] {
				return nil, fmt.Errorf("invalid scope: %s", s)
			}
		}
	}

	// Generate unique auth_req_id
	authReqID, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth_req_id: %w", err)
	}

	// Determine expiration (default 120 seconds, or requested_expiry if provided)
	expiresIn := 120
	if req.RequestedExpiry > 0 && req.RequestedExpiry <= 300 {
		expiresIn = req.RequestedExpiry
	}
	interval := 5 // Polling interval

	// Store CIBA request
	cibaReq := &database.CIBAAuthenticationRequest{
		AuthReqID:         authReqID,
		ApplicationID:     app.ID,
		UserID:            &user.ID,
		BindingMessage:    req.BindingMessage,
		ClientNotifyToken: req.ClientNotifyToken,
		Scope:             scope,
		ACRValues:         req.ACRValues,
		LoginHint:         req.LoginHint,
		LoginHintToken:    req.LoginHintToken,
		IDTokenHint:       req.IDTokenHint,
		RequestedExpiry:   req.RequestedExpiry,
		ExpiresAt:         time.Now().Add(time.Duration(expiresIn) * time.Second),
		Interval:          interval,
		Status:            "pending",
	}

	if err := s.db.Create(cibaReq).Error; err != nil {
		return nil, fmt.Errorf("failed to store CIBA request: %w", err)
	}

	// In a real implementation, this is where you would:
	// 1. Send a push notification to the user's device
	// 2. Send an SMS or email to the user
	// 3. Trigger any out-of-band authentication mechanism
	// For this implementation, we'll just record the request and let the user
	// authorize via the /oauth/ciba/authorize endpoint

	return &CIBAAuthenticationResponse{
		AuthReqID: authReqID,
		ExpiresIn: expiresIn,
		Interval:  interval,
	}, nil
}

// CIBAGrant handles the CIBA grant flow (token polling)
func (s *Server) CIBAGrant(req *TokenRequest) (*tokens.TokenResponse, error) {
	// Validate client credentials
	var app database.Application
	if err := s.db.Preload("Scopes").Where("client_id = ?", req.ClientID).First(&app).Error; err != nil {
		return nil, errors.New("invalid client")
	}

	// Verify client secret
	if err := s.verifyClientSecret(&app, req.ClientSecret); err != nil {
		return nil, errors.New("invalid client credentials")
	}

	// Find CIBA request
	var cibaReq database.CIBAAuthenticationRequest
	if err := s.db.Preload("User").Where("auth_req_id = ? AND application_id = ?", req.AuthReqID, app.ID).First(&cibaReq).Error; err != nil {
		return nil, errors.New("invalid auth_req_id")
	}

	// Check expiration
	if time.Now().After(cibaReq.ExpiresAt) {
		s.db.Model(&cibaReq).Update("status", "expired")
		return nil, &CIBAError{Code: "expired_token", Description: "authentication request has expired"}
	}

	// Check polling rate (slow_down error)
	if cibaReq.LastPollAt != nil {
		timeSinceLastPoll := time.Since(*cibaReq.LastPollAt)
		if timeSinceLastPoll < time.Duration(cibaReq.Interval)*time.Second {
			return nil, &CIBAError{Code: "slow_down", Description: "polling too frequently"}
		}
	}

	// Update last poll time
	now := time.Now()
	s.db.Model(&cibaReq).Update("last_poll_at", now)

	// Check status
	switch cibaReq.Status {
	case "pending":
		return nil, &CIBAError{Code: "authorization_pending", Description: "user has not yet authenticated"}
	case "denied":
		return nil, &CIBAError{Code: "access_denied", Description: "user denied the authentication request"}
	case "authorized":
		// Continue to token generation
	default:
		return nil, errors.New("invalid authentication request status")
	}

	// Get the authenticated user
	var user *database.User
	if cibaReq.UserID != nil {
		user = &database.User{}
		if err := s.db.Preload("Roles").Where("id = ?", cibaReq.UserID).First(user).Error; err != nil {
			return nil, errors.New("user not found")
		}
	} else {
		return nil, errors.New("no user associated with authentication request")
	}

	// Generate tokens
	accessToken, err := s.TokenManager.GenerateAccessToken(&app, user, cibaReq.Scope, "", nil)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.TokenManager.GenerateRefreshToken(&app, user, cibaReq.Scope)
	if err != nil {
		return nil, err
	}

	response := &tokens.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        cibaReq.Scope,
	}

	// Generate ID token if openid scope is present
	if strings.Contains(cibaReq.Scope, "openid") && user != nil {
		idToken, err := s.TokenManager.GenerateIDToken(&app, user, "", *cibaReq.AuthorizedAt)
		if err != nil {
			return nil, err
		}
		response.IDToken = idToken
	}

	// Store tokens
	s.storeTokens(&app, user, accessToken, refreshToken)

	// Mark CIBA request as consumed (delete)
	s.db.Delete(&cibaReq)

	return response, nil
}

// AuthorizeCIBARequest authorizes a CIBA authentication request
func (s *Server) AuthorizeCIBARequest(authReqID string, user *database.User) error {
	var cibaReq database.CIBAAuthenticationRequest
	if err := s.db.Where("auth_req_id = ?", authReqID).First(&cibaReq).Error; err != nil {
		return errors.New("invalid auth_req_id")
	}

	// Check expiration
	if time.Now().After(cibaReq.ExpiresAt) {
		s.db.Model(&cibaReq).Update("status", "expired")
		return errors.New("authentication request has expired")
	}

	// Check if already processed
	if cibaReq.Status != "pending" {
		return errors.New("authentication request already processed")
	}

	// Verify the authorizing user matches the requested user
	if cibaReq.UserID != nil && *cibaReq.UserID != user.ID {
		return errors.New("user mismatch - you are not authorized to approve this request")
	}

	// Authorize the request
	now := time.Now()
	updates := map[string]interface{}{
		"status":        "authorized",
		"authorized_at": now,
	}

	if err := s.db.Model(&cibaReq).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to authorize CIBA request: %w", err)
	}

	return nil
}

// DenyCIBARequest denies a CIBA authentication request
func (s *Server) DenyCIBARequest(authReqID string) error {
	var cibaReq database.CIBAAuthenticationRequest
	if err := s.db.Where("auth_req_id = ?", authReqID).First(&cibaReq).Error; err != nil {
		return errors.New("invalid auth_req_id")
	}

	// Check expiration
	if time.Now().After(cibaReq.ExpiresAt) {
		s.db.Model(&cibaReq).Update("status", "expired")
		return errors.New("authentication request has expired")
	}

	// Check if already processed
	if cibaReq.Status != "pending" {
		return errors.New("authentication request already processed")
	}

	// Deny the request
	if err := s.db.Model(&cibaReq).Update("status", "denied").Error; err != nil {
		return fmt.Errorf("failed to deny CIBA request: %w", err)
	}

	return nil
}

// GetCIBARequestByAuthReqID retrieves CIBA request info (for authorization UI)
func (s *Server) GetCIBARequestByAuthReqID(authReqID string) (*database.CIBAAuthenticationRequest, *database.Application, error) {
	var cibaReq database.CIBAAuthenticationRequest
	if err := s.db.Where("auth_req_id = ?", authReqID).First(&cibaReq).Error; err != nil {
		return nil, nil, errors.New("invalid auth_req_id")
	}

	// Check expiration
	if time.Now().After(cibaReq.ExpiresAt) {
		s.db.Model(&cibaReq).Update("status", "expired")
		return nil, nil, errors.New("authentication request has expired")
	}

	// Check if already processed
	if cibaReq.Status != "pending" {
		return nil, nil, errors.New("authentication request already processed")
	}

	// Get application
	var app database.Application
	if err := s.db.Where("id = ?", cibaReq.ApplicationID).First(&app).Error; err != nil {
		return nil, nil, errors.New("application not found")
	}

	return &cibaReq, &app, nil
}
