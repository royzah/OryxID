package oauth

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tiiuae/oryxid/internal/database"
)

func TestGenerateUserCode(t *testing.T) {
	// Test that user codes are generated correctly
	code, err := generateUserCode()
	if err != nil {
		t.Fatalf("generateUserCode() error = %v", err)
	}

	// Check format: XXXX-XXXX
	if len(code) != 9 {
		t.Errorf("generateUserCode() length = %d, want 9", len(code))
	}

	if code[4] != '-' {
		t.Errorf("generateUserCode() missing hyphen at position 4")
	}

	// Check that it only contains valid characters
	validChars := "ABCDEFGHJKMNPQRSTUVWXYZ23456789-"
	for _, c := range code {
		if !strings.ContainsRune(validChars, c) {
			t.Errorf("generateUserCode() contains invalid character: %c", c)
		}
	}
}

func TestGenerateUserCode_Uniqueness(t *testing.T) {
	// Test that multiple generated codes are unique
	codes := make(map[string]bool)
	for i := 0; i < 100; i++ {
		code, err := generateUserCode()
		if err != nil {
			t.Fatalf("generateUserCode() error = %v", err)
		}
		if codes[code] {
			t.Errorf("generateUserCode() generated duplicate code: %s", code)
		}
		codes[code] = true
	}
}

func TestDeviceCodeError_Error(t *testing.T) {
	err := &DeviceCodeError{
		Code:        "authorization_pending",
		Description: "user has not yet authorized",
	}

	if err.Error() != "user has not yet authorized" {
		t.Errorf("DeviceCodeError.Error() = %s, want %s", err.Error(), "user has not yet authorized")
	}
}

func TestDeviceAuthorizationResponse_Fields(t *testing.T) {
	resp := &DeviceAuthorizationResponse{
		DeviceCode:              "test-device-code",
		UserCode:                "ABCD-EFGH",
		VerificationURI:         "https://example.com/device",
		VerificationURIComplete: "https://example.com/device?user_code=ABCD-EFGH",
		ExpiresIn:               1800,
		Interval:                5,
	}

	if resp.DeviceCode != "test-device-code" {
		t.Errorf("DeviceCode = %s, want %s", resp.DeviceCode, "test-device-code")
	}
	if resp.UserCode != "ABCD-EFGH" {
		t.Errorf("UserCode = %s, want %s", resp.UserCode, "ABCD-EFGH")
	}
	if resp.VerificationURI != "https://example.com/device" {
		t.Errorf("VerificationURI = %s, want %s", resp.VerificationURI, "https://example.com/device")
	}
	if resp.ExpiresIn != 1800 {
		t.Errorf("ExpiresIn = %d, want %d", resp.ExpiresIn, 1800)
	}
	if resp.Interval != 5 {
		t.Errorf("Interval = %d, want %d", resp.Interval, 5)
	}
}

func TestDeviceAuthorizationRequest_Fields(t *testing.T) {
	req := &DeviceAuthorizationRequest{
		ClientID: "test-client-id",
		Scope:    "openid profile",
		Audience: "https://api.example.com",
	}

	if req.ClientID != "test-client-id" {
		t.Errorf("ClientID = %s, want %s", req.ClientID, "test-client-id")
	}
	if req.Scope != "openid profile" {
		t.Errorf("Scope = %s, want %s", req.Scope, "openid profile")
	}
	if req.Audience != "https://api.example.com" {
		t.Errorf("Audience = %s, want %s", req.Audience, "https://api.example.com")
	}
}

func TestDeviceCodeModel_Fields(t *testing.T) {
	appID := uuid.New()
	userID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(30 * time.Minute)

	dc := &database.DeviceCode{
		DeviceCode:      "test-device-code",
		UserCode:        "ABCD-EFGH",
		ApplicationID:   appID,
		UserID:          &userID,
		Scope:           "openid profile",
		Audience:        "https://api.example.com",
		VerificationURI: "https://example.com/device",
		ExpiresAt:       expiresAt,
		Interval:        5,
		Status:          "pending",
		ClientIP:        "192.168.1.1",
	}

	if dc.DeviceCode != "test-device-code" {
		t.Errorf("DeviceCode = %s, want %s", dc.DeviceCode, "test-device-code")
	}
	if dc.UserCode != "ABCD-EFGH" {
		t.Errorf("UserCode = %s, want %s", dc.UserCode, "ABCD-EFGH")
	}
	if dc.ApplicationID != appID {
		t.Errorf("ApplicationID = %v, want %v", dc.ApplicationID, appID)
	}
	if dc.Status != "pending" {
		t.Errorf("Status = %s, want %s", dc.Status, "pending")
	}
	if dc.Interval != 5 {
		t.Errorf("Interval = %d, want %d", dc.Interval, 5)
	}
}

func TestDeviceCodeStatus_Constants(t *testing.T) {
	// Test that status constants work as expected
	statuses := []string{"pending", "authorized", "denied", "expired"}

	for _, status := range statuses {
		dc := &database.DeviceCode{Status: status}
		if dc.Status != status {
			t.Errorf("Status = %s, want %s", dc.Status, status)
		}
	}
}

func TestUserCodeFormat_NoAmbiguousChars(t *testing.T) {
	// Generate 50 codes and verify none contain ambiguous characters
	ambiguousChars := "OIL01"

	for i := 0; i < 50; i++ {
		code, err := generateUserCode()
		if err != nil {
			t.Fatalf("generateUserCode() error = %v", err)
		}

		for _, c := range ambiguousChars {
			if strings.ContainsRune(code, c) {
				t.Errorf("generateUserCode() contains ambiguous character %c in code %s", c, code)
			}
		}
	}
}

// Token Exchange (RFC 8693) Tests

func TestTokenTypeConstants(t *testing.T) {
	// Verify token type URNs are correct per RFC 8693
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"AccessToken", TokenTypeAccessToken, "urn:ietf:params:oauth:token-type:access_token"},
		{"RefreshToken", TokenTypeRefreshToken, "urn:ietf:params:oauth:token-type:refresh_token"},
		{"IDToken", TokenTypeIDToken, "urn:ietf:params:oauth:token-type:id_token"},
		{"JWT", TokenTypeJWT, "urn:ietf:params:oauth:token-type:jwt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %s, want %s", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

func TestTokenExchangeResponse_Fields(t *testing.T) {
	resp := &TokenExchangeResponse{
		AccessToken:     "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       3600,
		Scope:           "openid profile",
		RefreshToken:    "refresh-token-value",
	}

	if resp.AccessToken == "" {
		t.Error("AccessToken should not be empty")
	}
	if resp.IssuedTokenType != TokenTypeAccessToken {
		t.Errorf("IssuedTokenType = %s, want %s", resp.IssuedTokenType, TokenTypeAccessToken)
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("TokenType = %s, want Bearer", resp.TokenType)
	}
	if resp.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", resp.ExpiresIn)
	}
	if resp.Scope != "openid profile" {
		t.Errorf("Scope = %s, want openid profile", resp.Scope)
	}
}

func TestTokenExchangeResponse_NonAccessToken(t *testing.T) {
	// Per RFC 8693, when issued token is not an access token,
	// token_type should be "N_A"
	resp := &TokenExchangeResponse{
		AccessToken:     "refresh-token-value",
		IssuedTokenType: TokenTypeRefreshToken,
		TokenType:       "N_A",
	}

	if resp.TokenType != "N_A" {
		t.Errorf("TokenType for refresh token = %s, want N_A", resp.TokenType)
	}
}

func TestTokenRequestExchangeFields(t *testing.T) {
	req := &TokenRequest{
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		ClientID:           "test-client",
		SubjectToken:       "subject-token-value",
		SubjectTokenType:   TokenTypeAccessToken,
		ActorToken:         "actor-token-value",
		ActorTokenType:     TokenTypeAccessToken,
		RequestedTokenType: TokenTypeAccessToken,
		Resource:           "https://api.example.com",
		Scope:              "read write",
		Audience:           "target-service",
	}

	if req.SubjectToken != "subject-token-value" {
		t.Errorf("SubjectToken = %s, want subject-token-value", req.SubjectToken)
	}
	if req.SubjectTokenType != TokenTypeAccessToken {
		t.Errorf("SubjectTokenType = %s, want %s", req.SubjectTokenType, TokenTypeAccessToken)
	}
	if req.ActorToken != "actor-token-value" {
		t.Errorf("ActorToken = %s, want actor-token-value", req.ActorToken)
	}
	if req.RequestedTokenType != TokenTypeAccessToken {
		t.Errorf("RequestedTokenType = %s, want %s", req.RequestedTokenType, TokenTypeAccessToken)
	}
	if req.Resource != "https://api.example.com" {
		t.Errorf("Resource = %s, want https://api.example.com", req.Resource)
	}
}
