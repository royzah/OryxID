package oauth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DPoP implements RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession
// DPoP binds access tokens to a specific client by requiring proof of private key possession

const (
	// DPoPHeaderType is the typ header value for DPoP proofs
	DPoPHeaderType = "dpop+jwt"
	// DPoPMaxClockSkew is the maximum allowed clock skew for DPoP proof validation
	DPoPMaxClockSkew = 5 * time.Minute
	// DPoPMaxAge is the maximum age of a DPoP proof
	DPoPMaxAge = 5 * time.Minute
)

// DPoPProof represents a parsed DPoP proof JWT
type DPoPProof struct {
	// Header fields
	Type      string          `json:"typ"`
	Algorithm string          `json:"alg"`
	JWK       json.RawMessage `json:"jwk"`

	// Claims
	JTI        string `json:"jti"`   // Unique identifier
	HTTPMethod string `json:"htm"`   // HTTP method
	HTTPUri    string `json:"htu"`   // HTTP URI
	IssuedAt   int64  `json:"iat"`   // Issued at timestamp
	ATH        string `json:"ath"`   // Access token hash (for resource requests)
	Nonce      string `json:"nonce"` // Server-provided nonce (optional)

	// Parsed public key
	PublicKey crypto.PublicKey
	// JWK thumbprint (for token binding)
	Thumbprint string
}

// DPoPValidator validates DPoP proofs
type DPoPValidator struct {
	// usedJTIs tracks used JTI values to prevent replay attacks
	// In production, use Redis or database for distributed systems
	usedJTIs map[string]time.Time
	// currentNonce is the server-provided nonce (optional)
	currentNonce string
}

// NewDPoPValidator creates a new DPoP validator
func NewDPoPValidator() *DPoPValidator {
	return &DPoPValidator{
		usedJTIs: make(map[string]time.Time),
	}
}

// ValidateProof validates a DPoP proof JWT
func (v *DPoPValidator) ValidateProof(proofJWT, httpMethod, httpURI, accessToken string) (*DPoPProof, error) {
	if proofJWT == "" {
		return nil, errors.New("dpop proof is required")
	}

	// Parse JWT without verification first to get the header
	parts := strings.Split(proofJWT, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid dpop proof format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid dpop header encoding: %w", err)
	}

	var header struct {
		Type      string          `json:"typ"`
		Algorithm string          `json:"alg"`
		JWK       json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("invalid dpop header: %w", err)
	}

	// Validate header
	if header.Type != DPoPHeaderType {
		return nil, fmt.Errorf("invalid dpop typ: expected %s, got %s", DPoPHeaderType, header.Type)
	}

	if header.JWK == nil {
		return nil, errors.New("dpop proof must contain jwk in header")
	}

	// Parse the JWK to get the public key
	publicKey, err := parseJWK(header.JWK)
	if err != nil {
		return nil, fmt.Errorf("invalid dpop jwk: %w", err)
	}

	// Calculate JWK thumbprint
	thumbprint, err := calculateJWKThumbprint(header.JWK)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate jwk thumbprint: %w", err)
	}

	// Now verify the JWT signature
	token, err := jwt.Parse(proofJWT, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("invalid dpop signature: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid dpop claims")
	}

	// Extract and validate claims
	proof := &DPoPProof{
		Type:       header.Type,
		Algorithm:  header.Algorithm,
		JWK:        header.JWK,
		PublicKey:  publicKey,
		Thumbprint: thumbprint,
	}

	// JTI (required)
	if jti, ok := claims["jti"].(string); ok {
		proof.JTI = jti
	} else {
		return nil, errors.New("dpop proof missing jti claim")
	}

	// Check JTI for replay
	if v.isJTIUsed(proof.JTI) {
		return nil, errors.New("dpop proof jti already used (replay attack)")
	}

	// HTM (required)
	if htm, ok := claims["htm"].(string); ok {
		proof.HTTPMethod = htm
	} else {
		return nil, errors.New("dpop proof missing htm claim")
	}

	// Validate HTTP method
	if !strings.EqualFold(proof.HTTPMethod, httpMethod) {
		return nil, fmt.Errorf("dpop htm mismatch: expected %s, got %s", httpMethod, proof.HTTPMethod)
	}

	// HTU (required)
	if htu, ok := claims["htu"].(string); ok {
		proof.HTTPUri = htu
	} else {
		return nil, errors.New("dpop proof missing htu claim")
	}

	// Validate HTTP URI (ignore query string and fragment)
	if !validateHTU(proof.HTTPUri, httpURI) {
		return nil, fmt.Errorf("dpop htu mismatch: expected %s, got %s", httpURI, proof.HTTPUri)
	}

	// IAT (required)
	if iat, ok := claims["iat"].(float64); ok {
		proof.IssuedAt = int64(iat)
	} else {
		return nil, errors.New("dpop proof missing iat claim")
	}

	// Validate IAT (not too old, not in future)
	now := time.Now()
	iatTime := time.Unix(proof.IssuedAt, 0)
	if iatTime.After(now.Add(DPoPMaxClockSkew)) {
		return nil, errors.New("dpop proof iat is in the future")
	}
	if iatTime.Before(now.Add(-DPoPMaxAge)) {
		return nil, errors.New("dpop proof has expired")
	}

	// ATH (optional, required when presenting access token)
	if ath, ok := claims["ath"].(string); ok {
		proof.ATH = ath
	}

	// If access token is provided, validate ATH
	if accessToken != "" {
		expectedATH := calculateAccessTokenHash(accessToken)
		if proof.ATH != expectedATH {
			return nil, errors.New("dpop ath does not match access token")
		}
	}

	// Nonce (optional)
	if nonce, ok := claims["nonce"].(string); ok {
		proof.Nonce = nonce
	}

	// Mark JTI as used
	v.markJTIUsed(proof.JTI)

	return proof, nil
}

// GetThumbprint returns the JWK thumbprint for token binding
func (p *DPoPProof) GetThumbprint() string {
	return p.Thumbprint
}

// isJTIUsed checks if a JTI has been used recently
func (v *DPoPValidator) isJTIUsed(jti string) bool {
	if ts, exists := v.usedJTIs[jti]; exists {
		// Clean up old entries
		if time.Since(ts) > DPoPMaxAge*2 {
			delete(v.usedJTIs, jti)
			return false
		}
		return true
	}
	return false
}

// markJTIUsed marks a JTI as used
func (v *DPoPValidator) markJTIUsed(jti string) {
	v.usedJTIs[jti] = time.Now()

	// Periodic cleanup of old JTIs
	if len(v.usedJTIs) > 10000 {
		cutoff := time.Now().Add(-DPoPMaxAge * 2)
		for k, ts := range v.usedJTIs {
			if ts.Before(cutoff) {
				delete(v.usedJTIs, k)
			}
		}
	}
}

// parseJWK parses a JWK JSON into a public key
func parseJWK(jwkJSON json.RawMessage) (crypto.PublicKey, error) {
	var jwk struct {
		Kty string `json:"kty"`
		// RSA fields
		N string `json:"n"`
		E string `json:"e"`
		// EC fields
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}

	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return nil, err
	}

	switch jwk.Kty {
	case "RSA":
		return parseRSAPublicKey(jwk.N, jwk.E)
	case "EC":
		return parseECPublicKey(jwk.Crv, jwk.X, jwk.Y)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// parseRSAPublicKey parses RSA JWK components into a public key
func parseRSAPublicKey(nBase64, eBase64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA n: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA e: %w", err)
	}

	// Convert e bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}

	key := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}

	return key, nil
}

// parseECPublicKey parses EC JWK components into a public key
func parseECPublicKey(crv, xBase64, yBase64 string) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(xBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid EC x: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(yBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid EC y: %w", err)
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	key := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	return key, nil
}

// calculateJWKThumbprint calculates the JWK thumbprint per RFC 7638
func calculateJWKThumbprint(jwkJSON json.RawMessage) (string, error) {
	var jwk map[string]interface{}
	if err := json.Unmarshal(jwkJSON, &jwk); err != nil {
		return "", err
	}

	kty, _ := jwk["kty"].(string)

	// Build canonical JWK representation (only required members, sorted)
	var canonical map[string]interface{}
	switch kty {
	case "RSA":
		canonical = map[string]interface{}{
			"e":   jwk["e"],
			"kty": kty,
			"n":   jwk["n"],
		}
	case "EC":
		canonical = map[string]interface{}{
			"crv": jwk["crv"],
			"kty": kty,
			"x":   jwk["x"],
			"y":   jwk["y"],
		}
	default:
		return "", fmt.Errorf("unsupported key type for thumbprint: %s", kty)
	}

	// JSON encode with sorted keys (Go's json.Marshal sorts keys)
	thumbprintInput, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}

	// SHA-256 hash
	hash := sha256.Sum256(thumbprintInput)

	// Base64url encode
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// calculateAccessTokenHash calculates the ath claim value
func calculateAccessTokenHash(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// validateHTU validates the htu claim against the request URI
func validateHTU(htu, requestURI string) bool {
	// Remove query string and fragment from both
	htuBase := strings.Split(strings.Split(htu, "?")[0], "#")[0]
	reqBase := strings.Split(strings.Split(requestURI, "?")[0], "#")[0]
	return strings.EqualFold(htuBase, reqBase)
}

// DPoPBoundToken represents a DPoP-bound access token
type DPoPBoundToken struct {
	AccessToken string
	TokenType   string // "DPoP"
	Thumbprint  string // jkt claim value
}

// CreateDPoPBoundTokenClaims adds DPoP binding claims to token
func CreateDPoPBoundTokenClaims(thumbprint string) map[string]interface{} {
	return map[string]interface{}{
		"cnf": map[string]string{
			"jkt": thumbprint,
		},
	}
}

// ValidateDPoPBinding validates that a DPoP proof matches a token's binding
func ValidateDPoPBinding(tokenClaims map[string]interface{}, proofThumbprint string) error {
	cnf, ok := tokenClaims["cnf"].(map[string]interface{})
	if !ok {
		return errors.New("token does not have cnf claim (not DPoP-bound)")
	}

	jkt, ok := cnf["jkt"].(string)
	if !ok {
		return errors.New("token cnf claim does not have jkt")
	}

	if jkt != proofThumbprint {
		return errors.New("dpop proof thumbprint does not match token binding")
	}

	return nil
}
