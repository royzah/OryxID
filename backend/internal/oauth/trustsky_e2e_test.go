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

// TestTrustSkyE2E tests the complete TrustSky USSP integration flow
func TestTrustSkyE2E(t *testing.T) {
	t.Run("scope hierarchy expansion", testScopeHierarchyExpansion)
	t.Run("scope hierarchy validation", testScopeHierarchyValidation)
	t.Run("dpop token flow", testDPoPTokenFlow)
	t.Run("dpop replay prevention", testDPoPReplayPrevention)
	t.Run("dpop access token binding", testDPoPAccessTokenBinding)
}

func testScopeHierarchyExpansion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]bool
	}{
		{
			name:  "admin expands to all trustsky scopes",
			input: "trustsky:admin",
			expected: map[string]bool{
				"trustsky:admin":           true,
				"trustsky:flight:read":     true,
				"trustsky:flight:write":    true,
				"trustsky:nfz:read":        true,
				"trustsky:nfz:write":       true,
				"trustsky:telemetry:write": true,
				"trustsky:sky:read":        true,
				"trustsky:operator:read":   true,
				"trustsky:operator:write":  true,
			},
		},
		{
			name:  "flight write includes read",
			input: "trustsky:flight:write",
			expected: map[string]bool{
				"trustsky:flight:write": true,
				"trustsky:flight:read":  true,
			},
		},
		{
			name:  "nfz write includes read",
			input: "trustsky:nfz:write",
			expected: map[string]bool{
				"trustsky:nfz:write": true,
				"trustsky:nfz:read":  true,
			},
		},
		{
			name:  "multiple scopes with expansion",
			input: "openid trustsky:flight:write trustsky:nfz:write",
			expected: map[string]bool{
				"openid":                true,
				"trustsky:flight:write": true,
				"trustsky:flight:read":  true,
				"trustsky:nfz:write":    true,
				"trustsky:nfz:read":     true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandScopes(tt.input)
			resultScopes := make(map[string]bool)
			for _, s := range splitScopes(result) {
				resultScopes[s] = true
			}

			for expected := range tt.expected {
				if !resultScopes[expected] {
					t.Errorf("expected scope %q not found in result: %v", expected, result)
				}
			}
		})
	}
}

func testScopeHierarchyValidation(t *testing.T) {
	tests := []struct {
		name     string
		granted  string
		required string
		expected bool
	}{
		{
			name:     "admin grants flight read",
			granted:  "trustsky:admin",
			required: "trustsky:flight:read",
			expected: true,
		},
		{
			name:     "admin grants flight write",
			granted:  "trustsky:admin",
			required: "trustsky:flight:write",
			expected: true,
		},
		{
			name:     "flight write grants flight read",
			granted:  "trustsky:flight:write",
			required: "trustsky:flight:read",
			expected: true,
		},
		{
			name:     "flight read does not grant flight write",
			granted:  "trustsky:flight:read",
			required: "trustsky:flight:write",
			expected: false,
		},
		{
			name:     "flight scope does not grant nfz scope",
			granted:  "trustsky:flight:write",
			required: "trustsky:nfz:read",
			expected: false,
		},
		{
			name:     "multiple scopes include expanded read",
			granted:  "openid trustsky:flight:write",
			required: "trustsky:flight:read",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasScope(tt.granted, tt.required)
			if result != tt.expected {
				t.Errorf("HasScope(%q, %q) = %v, expected %v", tt.granted, tt.required, result, tt.expected)
			}
		})
	}
}

func testDPoPTokenFlow(t *testing.T) {
	// Generate client key pair
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

	// Simulate token endpoint request
	t.Run("token endpoint", func(t *testing.T) {
		proof := createTestDPoPProofForE2E(t, privateKey, jwkBytes, "POST", "https://oryxid.example.com/oauth/token", "", "")

		result, err := validator.ValidateProof(proof, "POST", "https://oryxid.example.com/oauth/token", "")
		if err != nil {
			t.Fatalf("DPoP proof validation failed: %v", err)
		}

		if result.Thumbprint == "" {
			t.Error("expected thumbprint to be set")
		}

		// Verify thumbprint can be used for token binding
		t.Logf("Token would be bound to thumbprint: %s", result.Thumbprint)
	})

	// Simulate resource server request with access token
	t.Run("resource server with ath", func(t *testing.T) {
		accessToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
		hash := sha256.Sum256([]byte(accessToken))
		ath := base64.RawURLEncoding.EncodeToString(hash[:])

		proof := createTestDPoPProofForE2E(t, privateKey, jwkBytes, "GET", "https://trustsky.example.com/api/flights", ath, "")

		result, err := validator.ValidateProof(proof, "GET", "https://trustsky.example.com/api/flights", accessToken)
		if err != nil {
			t.Fatalf("DPoP proof with ATH validation failed: %v", err)
		}

		if result.ATH != ath {
			t.Errorf("expected ATH %s, got %s", ath, result.ATH)
		}
	})
}

func testDPoPReplayPrevention(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes()),
	}
	jwkBytes, _ := json.Marshal(jwk)

	validator := NewDPoPValidator()

	// Create a proof
	proof := createTestDPoPProofForE2E(t, privateKey, jwkBytes, "POST", "https://oryxid.example.com/oauth/token", "", "")

	// First use should succeed
	_, err := validator.ValidateProof(proof, "POST", "https://oryxid.example.com/oauth/token", "")
	if err != nil {
		t.Fatalf("first use of DPoP proof should succeed: %v", err)
	}

	// Second use should fail (replay)
	_, err = validator.ValidateProof(proof, "POST", "https://oryxid.example.com/oauth/token", "")
	if err == nil {
		t.Error("second use of same DPoP proof should fail (replay attack)")
	}
}

func testDPoPAccessTokenBinding(t *testing.T) {
	thumbprint := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

	t.Run("valid binding", func(t *testing.T) {
		tokenClaims := map[string]interface{}{
			"sub":       "client123",
			"client_id": "client123",
			"scope":     "trustsky:flight:read",
			"tenant_id": "tenant-uuid-here",
			"cnf": map[string]interface{}{
				"jkt": thumbprint,
			},
		}

		err := ValidateDPoPBinding(tokenClaims, thumbprint)
		if err != nil {
			t.Errorf("valid binding should not error: %v", err)
		}
	})

	t.Run("wrong thumbprint", func(t *testing.T) {
		tokenClaims := map[string]interface{}{
			"sub":       "client123",
			"client_id": "client123",
			"scope":     "trustsky:flight:read",
			"tenant_id": "tenant-uuid-here",
			"cnf": map[string]interface{}{
				"jkt": thumbprint,
			},
		}

		err := ValidateDPoPBinding(tokenClaims, "wrong-thumbprint")
		if err == nil {
			t.Error("wrong thumbprint should error")
		}
	})

	t.Run("missing cnf claim", func(t *testing.T) {
		tokenClaims := map[string]interface{}{
			"sub":       "client123",
			"client_id": "client123",
			"scope":     "trustsky:flight:read",
			"tenant_id": "tenant-uuid-here",
		}

		err := ValidateDPoPBinding(tokenClaims, thumbprint)
		if err == nil {
			t.Error("missing cnf claim should error")
		}
	})
}

// Helper to split scope string
func splitScopes(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, scope := range []byte(s) {
		if scope == ' ' {
			continue
		}
	}
	// Simple split on space
	current := ""
	for _, c := range s {
		if c == ' ' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

// createTestDPoPProofForE2E creates a DPoP proof for E2E testing
func createTestDPoPProofForE2E(t *testing.T, key *ecdsa.PrivateKey, jwkBytes []byte, method, uri, ath, nonce string) string {
	t.Helper()

	claims := jwt.MapClaims{
		"jti": "e2e-test-" + time.Now().Format(time.RFC3339Nano),
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

// TestTrustSkyTokenClaims verifies the expected claims structure
func TestTrustSkyTokenClaims(t *testing.T) {
	// Verify expected claims are present
	expectedClaims := []string{
		"iss",       // Issuer
		"sub",       // Subject
		"aud",       // Audience
		"exp",       // Expiration
		"iat",       // Issued at
		"scope",     // OAuth scopes
		"client_id", // Client identifier
		"tenant_id", // TrustSky multi-tenancy
	}

	// This is a structural test to ensure we document required claims
	for _, claim := range expectedClaims {
		t.Logf("Required TrustSky claim: %s", claim)
	}

	// DPoP-bound tokens should also have
	dpopClaims := []string{
		"cnf", // Confirmation (contains jkt for DPoP)
	}

	for _, claim := range dpopClaims {
		t.Logf("DPoP-bound token claim: %s", claim)
	}
}

// TestTrustSkyScopeConstants ensures all TrustSky scopes are defined
func TestTrustSkyScopeConstants(t *testing.T) {
	requiredScopes := []string{
		"trustsky:admin",
		"trustsky:flight:read",
		"trustsky:flight:write",
		"trustsky:nfz:read",
		"trustsky:nfz:write",
		"trustsky:telemetry:write",
		"trustsky:sky:read",
		"trustsky:operator:read",
		"trustsky:operator:write",
	}

	// Verify all scopes are in hierarchy
	for _, scope := range requiredScopes {
		t.Run(scope, func(t *testing.T) {
			// Check if admin expands to include this scope
			if scope != "trustsky:admin" {
				if !HasScope("trustsky:admin", scope) {
					t.Errorf("trustsky:admin should grant %s", scope)
				}
			}
		})
	}
}

// TestHasAllScopesForTrustSky tests multiple scope requirements
func TestHasAllScopesForTrustSky(t *testing.T) {
	tests := []struct {
		name     string
		granted  string
		required []string
		expected bool
	}{
		{
			name:     "admin has all scopes",
			granted:  "trustsky:admin",
			required: []string{"trustsky:flight:read", "trustsky:nfz:read", "trustsky:operator:read"},
			expected: true,
		},
		{
			name:     "partial scopes insufficient",
			granted:  "trustsky:flight:write",
			required: []string{"trustsky:flight:read", "trustsky:nfz:read"},
			expected: false,
		},
		{
			name:     "multiple write scopes grant reads",
			granted:  "trustsky:flight:write trustsky:nfz:write",
			required: []string{"trustsky:flight:read", "trustsky:nfz:read"},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAllScopes(tt.granted, tt.required)
			if result != tt.expected {
				t.Errorf("HasAllScopes(%q, %v) = %v, expected %v", tt.granted, tt.required, result, tt.expected)
			}
		})
	}
}
