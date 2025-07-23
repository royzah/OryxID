package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

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

	// Generate new access token
	accessToken, err := s.TokenManager.GenerateAccessToken(&app, user, claims.Scope, claims.Audience[0], nil)
	if err != nil {
		return nil, err
	}

	response := &tokens.TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: req.RefreshToken, // Return same refresh token
		Scope:        claims.Scope,
	}

	// Store new access token
	s.storeTokens(&app, user, accessToken, "")

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
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		computed := base64.URLEncoding.EncodeToString(h[:])
		// Remove padding for comparison
		computed = strings.TrimRight(computed, "=")
		challenge = strings.TrimRight(challenge, "=")
		return computed == challenge
	case "plain":
		return verifier == challenge
	default:
		return false
	}
}

func (s *Server) verifyClientSecret(app *database.Application, providedSecret string) error {
	// For public clients, don't check secret
	if app.ClientType == "public" {
		return nil
	}

	// Check if we have a hashed secret
	if app.HashedClientSecret != "" {
		// Use bcrypt to compare
		return bcrypt.CompareHashAndPassword([]byte(app.HashedClientSecret), []byte(providedSecret))
	}

	// Fallback to plain text comparison (for legacy support)
	if app.ClientSecret != providedSecret {
		return errors.New("invalid client secret")
	}

	return nil
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
		s.db.Create(token)
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
		s.db.Create(token)
	}
}
