package tokens

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tiiuae/oryxid/internal/config"
	"github.com/tiiuae/oryxid/internal/database"
)

type TokenManager struct {
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	signingMethod jwt.SigningMethod
	issuer        string
	kid           string
}

type CustomClaims struct {
	jwt.RegisteredClaims
	Scope         string                 `json:"scope,omitempty"`
	ClientID      string                 `json:"client_id,omitempty"`
	TenantID      string                 `json:"tenant_id,omitempty"` // Multi-tenancy: operator/organization UUID (TrustSky USSP)
	Username      string                 `json:"username,omitempty"`
	Email         string                 `json:"email,omitempty"`
	EmailVerified bool                   `json:"email_verified,omitempty"`
	Roles         []string               `json:"roles,omitempty"`
	Type          string                 `json:"typ,omitempty"`
	Nonce         string                 `json:"nonce,omitempty"`
	AuthTime      int64                  `json:"auth_time,omitempty"`
	Extra         map[string]interface{} `json:"ext,omitempty"`
}

type TokenResponse struct {
	AccessToken          string `json:"access_token"`
	TokenType            string `json:"token_type"`
	ExpiresIn            int    `json:"expires_in"`
	RefreshToken         string `json:"refresh_token,omitempty"`
	IDToken              string `json:"id_token,omitempty"`
	Scope                string `json:"scope,omitempty"`
	AuthorizationDetails string `json:"authorization_details,omitempty"` // RAR (RFC 9396) - JSON array
}

type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"` // Multi-tenancy: operator/organization UUID (TrustSky USSP)
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Nbf       int64  `json:"nbf,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	Jti       string `json:"jti,omitempty"`
}

func NewTokenManager(cfg *config.JWTConfig, issuer string) (*TokenManager, error) {
	return &TokenManager{
		privateKey:    cfg.PrivateKey,
		publicKey:     cfg.PublicKey,
		signingMethod: jwt.SigningMethodRS256,
		issuer:        issuer,
		kid:           cfg.Kid,
	}, nil
}

// GenerateAccessToken generates a JWT access token
// tenantID is optional - if the application has a tenant, it will be included in the token
func (tm *TokenManager) GenerateAccessToken(app *database.Application, user *database.User, scope, audience string, extra map[string]interface{}) (string, error) {
	now := time.Now()
	expiresAt := now.Add(time.Hour) // Default 1 hour, can be customized

	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tm.issuer,
			Subject:   app.ClientID,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		Scope:    scope,
		ClientID: app.ClientID,
		Type:     "Bearer",
		Extra:    extra,
	}

	// Add tenant_id if application has a tenant (TrustSky USSP integration)
	if app.TenantID != nil {
		claims.TenantID = app.TenantID.String()
	}

	// Add user info if present
	if user != nil {
		claims.Subject = user.ID.String()
		claims.Username = user.Username
		claims.Email = user.Email

		// Add roles
		roles := make([]string, len(user.Roles))
		for i, role := range user.Roles {
			roles[i] = role.Name
		}
		claims.Roles = roles
		claims.AuthTime = now.Unix()
	}

	token := jwt.NewWithClaims(tm.signingMethod, claims)
	token.Header["kid"] = tm.kid

	return token.SignedString(tm.privateKey)
}

// GenerateRefreshToken generates a JWT refresh token
func (tm *TokenManager) GenerateRefreshToken(app *database.Application, user *database.User, scope string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(30 * 24 * time.Hour) // Default 30 days

	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tm.issuer,
			Subject:   app.ClientID,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		Scope:    scope,
		ClientID: app.ClientID,
		Type:     "Refresh",
	}

	if user != nil {
		claims.Subject = user.ID.String()
	}

	token := jwt.NewWithClaims(tm.signingMethod, claims)
	token.Header["kid"] = tm.kid

	return token.SignedString(tm.privateKey)
}

// GenerateIDToken generates an OpenID Connect ID token
func (tm *TokenManager) GenerateIDToken(app *database.Application, user *database.User, nonce string, authTime time.Time) (string, error) {
	if user == nil {
		return "", fmt.Errorf("user is required for ID token")
	}

	now := time.Now()
	expiresAt := now.Add(time.Hour)

	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tm.issuer,
			Subject:   user.ID.String(),
			Audience:  jwt.ClaimStrings{app.ClientID},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		Username:      user.Username,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Nonce:         nonce,
		AuthTime:      authTime.Unix(),
		Type:          "ID",
	}

	// Add roles
	roles := make([]string, len(user.Roles))
	for i, role := range user.Roles {
		roles[i] = role.Name
	}
	claims.Roles = roles

	token := jwt.NewWithClaims(tm.signingMethod, claims)
	token.Header["kid"] = tm.kid

	return token.SignedString(tm.privateKey)
}

// ValidateToken validates a JWT token and returns the claims
func (tm *TokenManager) ValidateToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// IntrospectToken validates a token and returns introspection response
func (tm *TokenManager) IntrospectToken(tokenString string) (*IntrospectionResponse, error) {
	claims, err := tm.ValidateToken(tokenString)
	if err != nil {
		return &IntrospectionResponse{Active: false}, nil
	}

	// Check if token is expired
	if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
		return &IntrospectionResponse{Active: false}, nil
	}

	// Extract audience (if present)
	aud := ""
	if len(claims.Audience) > 0 {
		aud = claims.Audience[0]
	}

	return &IntrospectionResponse{
		Active:    true,
		Scope:     claims.Scope,
		ClientID:  claims.ClientID,
		TenantID:  claims.TenantID, // Include tenant_id for TrustSky USSP integration
		Username:  claims.Username,
		TokenType: claims.Type,
		Exp:       claims.ExpiresAt.Unix(),
		Iat:       claims.IssuedAt.Unix(),
		Nbf:       claims.NotBefore.Unix(),
		Sub:       claims.Subject,
		Aud:       aud,
		Iss:       claims.Issuer,
		Jti:       claims.ID,
	}, nil
}

// GetJWKS returns the JSON Web Key Set with proper base64url encoding per RFC 7517
func (tm *TokenManager) GetJWKS() (map[string]interface{}, error) {
	// Encode modulus (n) as base64url without padding
	nBytes := tm.publicKey.N.Bytes()
	nBase64 := base64.RawURLEncoding.EncodeToString(nBytes)

	// Encode exponent (e) as base64url without padding
	// The exponent is typically 65537 (0x010001)
	e := tm.publicKey.E
	eBytes := make([]byte, 0)
	for e > 0 {
		eBytes = append([]byte{byte(e & 0xff)}, eBytes...)
		e >>= 8
	}
	eBase64 := base64.RawURLEncoding.EncodeToString(eBytes)

	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": tm.kid,
		"alg": "RS256",
		"n":   nBase64,
		"e":   eBase64,
	}

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{jwk},
	}

	return jwks, nil
}

// GenerateMFAToken generates a short-lived token for MFA verification
func (tm *TokenManager) GenerateMFAToken(user *database.User) (string, error) {
	now := time.Now()
	expiresAt := now.Add(5 * time.Minute) // MFA token valid for 5 minutes

	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tm.issuer,
			Subject:   user.ID.String(),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		Type: "MFA",
	}

	token := jwt.NewWithClaims(tm.signingMethod, claims)
	token.Header["kid"] = tm.kid

	return token.SignedString(tm.privateKey)
}

// ValidateMFAToken validates an MFA token and returns the user ID
func (tm *TokenManager) ValidateMFAToken(tokenString string) (string, error) {
	claims, err := tm.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	if claims.Type != "MFA" {
		return "", fmt.Errorf("invalid token type")
	}

	return claims.Subject, nil
}
