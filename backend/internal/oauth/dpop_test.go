package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestDPoPValidation(t *testing.T) {
	// Generate test EC key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create JWK from public key
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes()),
	}
	jwkBytes, _ := json.Marshal(jwk)

	validator := NewDPoPValidator()

	t.Run("valid proof", func(t *testing.T) {
		proof := createTestDPoPProof(t, privateKey, jwkBytes, "POST", "https://example.com/token", "", "")
		result, err := validator.ValidateProof(proof, "POST", "https://example.com/token", "")
		if err != nil {
			t.Errorf("expected valid proof, got error: %v", err)
		}
		if result == nil {
			t.Error("expected result, got nil")
		}
		if result.Thumbprint == "" {
			t.Error("expected thumbprint, got empty")
		}
	})

	t.Run("wrong HTTP method", func(t *testing.T) {
		proof := createTestDPoPProof(t, privateKey, jwkBytes, "POST", "https://example.com/token", "", "")
		_, err := validator.ValidateProof(proof, "GET", "https://example.com/token", "")
		if err == nil {
			t.Error("expected error for wrong HTTP method")
		}
	})

	t.Run("wrong URI", func(t *testing.T) {
		proof := createTestDPoPProof(t, privateKey, jwkBytes, "POST", "https://example.com/token", "", "")
		_, err := validator.ValidateProof(proof, "POST", "https://other.com/token", "")
		if err == nil {
			t.Error("expected error for wrong URI")
		}
	})

	t.Run("with access token hash", func(t *testing.T) {
		accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test"
		hash := sha256.Sum256([]byte(accessToken))
		ath := base64.RawURLEncoding.EncodeToString(hash[:])

		proof := createTestDPoPProof(t, privateKey, jwkBytes, "GET", "https://api.example.com/resource", ath, "")
		result, err := validator.ValidateProof(proof, "GET", "https://api.example.com/resource", accessToken)
		if err != nil {
			t.Errorf("expected valid proof with ATH, got error: %v", err)
		}
		if result.ATH != ath {
			t.Errorf("expected ATH %s, got %s", ath, result.ATH)
		}
	})

	t.Run("wrong access token hash", func(t *testing.T) {
		proof := createTestDPoPProof(t, privateKey, jwkBytes, "GET", "https://api.example.com/resource", "wrongath", "")
		_, err := validator.ValidateProof(proof, "GET", "https://api.example.com/resource", "sometoken")
		if err == nil {
			t.Error("expected error for wrong ATH")
		}
	})
}

func TestJWKThumbprint(t *testing.T) {
	// Test vector from RFC 7638
	jwk := json.RawMessage(`{"kty":"RSA","e":"AQAB","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}`)

	thumbprint, err := calculateJWKThumbprint(jwk)
	if err != nil {
		t.Fatalf("failed to calculate thumbprint: %v", err)
	}

	// Expected thumbprint from RFC 7638
	expected := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	if thumbprint != expected {
		t.Errorf("expected thumbprint %s, got %s", expected, thumbprint)
	}
}

func TestDPoPBinding(t *testing.T) {
	thumbprint := "test-thumbprint-123"

	t.Run("valid binding", func(t *testing.T) {
		claims := map[string]interface{}{
			"cnf": map[string]interface{}{
				"jkt": thumbprint,
			},
		}
		err := ValidateDPoPBinding(claims, thumbprint)
		if err != nil {
			t.Errorf("expected valid binding, got error: %v", err)
		}
	})

	t.Run("missing cnf", func(t *testing.T) {
		claims := map[string]interface{}{}
		err := ValidateDPoPBinding(claims, thumbprint)
		if err == nil {
			t.Error("expected error for missing cnf")
		}
	})

	t.Run("wrong thumbprint", func(t *testing.T) {
		claims := map[string]interface{}{
			"cnf": map[string]interface{}{
				"jkt": "different-thumbprint",
			},
		}
		err := ValidateDPoPBinding(claims, thumbprint)
		if err == nil {
			t.Error("expected error for wrong thumbprint")
		}
	})
}

// Helper to create test DPoP proofs
func createTestDPoPProof(t *testing.T, key *ecdsa.PrivateKey, jwkBytes []byte, method, uri, ath, nonce string) string {
	t.Helper()

	claims := jwt.MapClaims{
		"jti": "test-jti-" + time.Now().Format(time.RFC3339Nano),
		"htm": method,
		"htu": uri,
		"iat": time.Now().Unix(),
	}
	if ath != "" {
		claims["ath"] = ath
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = DPoPHeaderType
	token.Header["jwk"] = json.RawMessage(jwkBytes)

	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("failed to sign proof: %v", err)
	}

	return signed
}
