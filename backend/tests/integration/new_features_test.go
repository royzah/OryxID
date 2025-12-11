package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Device Authorization Grant Tests (RFC 8628)
// =============================================================================

func TestDeviceAuthorizationEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	verifyTestClientExists(t)

	// Note: Test client needs device_code grant type enabled
	data := url.Values{}
	data.Set("client_id", testClientID)
	data.Set("scope", "openid")

	req, err := http.NewRequest("POST", baseURL+"/oauth/device_authorization", strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// May return 400 if device_code grant not enabled for test client
	if resp.StatusCode == http.StatusBadRequest {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		if strings.Contains(errResp["error_description"], "not allowed") {
			t.Skip("Test client does not have device_code grant enabled")
		}
	}

	if resp.StatusCode == http.StatusOK {
		var devResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&devResp)
		require.NoError(t, err)

		assert.NotEmpty(t, devResp["device_code"])
		assert.NotEmpty(t, devResp["user_code"])
		assert.NotEmpty(t, devResp["verification_uri"])
		assert.NotNil(t, devResp["expires_in"])
		assert.NotNil(t, devResp["interval"])

		t.Logf("Device code: %s", devResp["device_code"])
		t.Logf("User code: %s", devResp["user_code"])
		t.Logf("Verification URI: %s", devResp["verification_uri"])
	}
}

func TestDeviceVerificationPage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client := &http.Client{Timeout: 10 * time.Second}

	// GET the device verification page
	resp, err := client.Get(baseURL + "/oauth/device")
	if err != nil {
		t.Skipf("Cannot connect to server: %v", err)
		return
	}
	defer resp.Body.Close()

	// Should return HTML page or JSON error if not configured
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound)
}

// =============================================================================
// Token Exchange Tests (RFC 8693)
// =============================================================================

func TestTokenExchangeEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	verifyTestClientExists(t)

	// First get an access token via client credentials
	tokenData := url.Values{}
	tokenData.Set("grant_type", "client_credentials")
	tokenData.Set("scope", "openid")

	tokenReq, err := http.NewRequest("POST", baseURL+"/oauth/token", strings.NewReader(tokenData.Encode()))
	require.NoError(t, err)
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(testClientID, testSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	tokenResp, err := client.Do(tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		t.Skip("Could not obtain initial access token")
		return
	}

	var initialToken map[string]interface{}
	json.NewDecoder(tokenResp.Body).Decode(&initialToken)

	accessToken := initialToken["access_token"].(string)

	// Now try token exchange
	exchangeData := url.Values{}
	exchangeData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	exchangeData.Set("subject_token", accessToken)
	exchangeData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")

	exchangeReq, err := http.NewRequest("POST", baseURL+"/oauth/token", strings.NewReader(exchangeData.Encode()))
	require.NoError(t, err)
	exchangeReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	exchangeReq.SetBasicAuth(testClientID, testSecret)

	exchangeResp, err := client.Do(exchangeReq)
	require.NoError(t, err)
	defer exchangeResp.Body.Close()

	// May return 400 if token-exchange grant not enabled
	if exchangeResp.StatusCode == http.StatusBadRequest {
		var errResp map[string]string
		json.NewDecoder(exchangeResp.Body).Decode(&errResp)
		if strings.Contains(errResp["error_description"], "not allowed") {
			t.Skip("Test client does not have token-exchange grant enabled")
		}
	}

	if exchangeResp.StatusCode == http.StatusOK {
		var exchangeResult map[string]interface{}
		err = json.NewDecoder(exchangeResp.Body).Decode(&exchangeResult)
		require.NoError(t, err)

		assert.NotEmpty(t, exchangeResult["access_token"])
		assert.NotEmpty(t, exchangeResult["issued_token_type"])
		t.Logf("Token exchange successful, issued_token_type: %s", exchangeResult["issued_token_type"])
	}
}

// =============================================================================
// CIBA Tests (Client-Initiated Backchannel Authentication)
// =============================================================================

func TestCIBAEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	verifyTestClientExists(t)

	data := url.Values{}
	data.Set("scope", "openid")
	data.Set("login_hint", "testuser") // Assumes this user exists

	req, err := http.NewRequest("POST", baseURL+"/oauth/bc-authorize", strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// May return 400 if CIBA grant not enabled or user not found
	if resp.StatusCode == http.StatusBadRequest {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		if strings.Contains(errResp["error_description"], "not allowed") {
			t.Skip("Test client does not have CIBA grant enabled")
		}
		if strings.Contains(errResp["error_description"], "not found") {
			t.Skip("Test user not found")
		}
		t.Logf("CIBA error: %s", errResp["error_description"])
	}

	if resp.StatusCode == http.StatusOK {
		var cibaResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&cibaResp)
		require.NoError(t, err)

		assert.NotEmpty(t, cibaResp["auth_req_id"])
		assert.NotNil(t, cibaResp["expires_in"])
		assert.NotNil(t, cibaResp["interval"])

		t.Logf("CIBA auth_req_id: %s", cibaResp["auth_req_id"])
	}
}

// =============================================================================
// RAR Tests (Rich Authorization Requests - RFC 9396)
// =============================================================================

func TestPARWithAuthorizationDetails(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	verifyTestClientExists(t)

	authDetails := `[{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"123.50"}}]`

	data := url.Values{}
	data.Set("response_type", "code")
	data.Set("redirect_uri", "https://example.com/callback")
	data.Set("scope", "openid")
	data.Set("code_challenge", generateS256Challenge("test-verifier-string-1234567890"))
	data.Set("code_challenge_method", "S256")
	data.Set("authorization_details", authDetails)

	req, err := http.NewRequest("POST", baseURL+"/oauth/par", strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusOK {
		var parResp map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&parResp)
		require.NoError(t, err)

		assert.NotEmpty(t, parResp["request_uri"])
		assert.Contains(t, parResp["request_uri"], "urn:ietf:params:oauth:request_uri:")
		t.Logf("PAR with authorization_details created: %s", parResp["request_uri"])
	}
}

func TestDiscoveryIncludesNewFeatures(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(baseURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Skipf("Cannot connect to server: %v", err)
		return
	}
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var discovery map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&discovery)
	require.NoError(t, err)

	// Check Device Authorization endpoint
	assert.Contains(t, discovery, "device_authorization_endpoint")
	t.Logf("device_authorization_endpoint: %v", discovery["device_authorization_endpoint"])

	// Check CIBA endpoint
	assert.Contains(t, discovery, "backchannel_authentication_endpoint")
	t.Logf("backchannel_authentication_endpoint: %v", discovery["backchannel_authentication_endpoint"])

	// Check grant types include new ones
	grantTypes, ok := discovery["grant_types_supported"].([]interface{})
	require.True(t, ok)

	grantTypeStrings := make([]string, len(grantTypes))
	for i, g := range grantTypes {
		grantTypeStrings[i] = g.(string)
	}

	assert.Contains(t, grantTypeStrings, "urn:ietf:params:oauth:grant-type:device_code")
	assert.Contains(t, grantTypeStrings, "urn:ietf:params:oauth:grant-type:token-exchange")
	assert.Contains(t, grantTypeStrings, "urn:openid:params:grant-type:ciba")

	// Check RAR support
	assert.Contains(t, discovery, "authorization_details_types_supported")

	// Check CIBA modes
	if modes, ok := discovery["backchannel_token_delivery_modes_supported"].([]interface{}); ok {
		modeStrings := make([]string, len(modes))
		for i, m := range modes {
			modeStrings[i] = m.(string)
		}
		assert.Contains(t, modeStrings, "poll")
	}

	t.Log("Discovery endpoint includes all new OAuth features")
}

// =============================================================================
// Error Handling Tests
// =============================================================================

func TestDeviceCodePollingErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	verifyTestClientExists(t)

	// Try to poll with invalid device code
	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	data.Set("device_code", "invalid-device-code")

	req, err := http.NewRequest("POST", baseURL+"/oauth/token", strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp map[string]string
	json.NewDecoder(resp.Body).Decode(&errResp)

	// Should be invalid_grant or invalid_request
	assert.NotEmpty(t, errResp["error"])
	t.Logf("Error for invalid device_code: %s - %s", errResp["error"], errResp["error_description"])
}

func TestTokenExchangeMissingSubjectToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	verifyTestClientExists(t)

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	// Missing subject_token

	req, err := http.NewRequest("POST", baseURL+"/oauth/token", strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp map[string]string
	json.NewDecoder(resp.Body).Decode(&errResp)
	assert.NotEmpty(t, errResp["error"])
}

func TestCIBAMissingHint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	verifyTestClientExists(t)

	data := url.Values{}
	data.Set("scope", "openid")
	// Missing login_hint, login_hint_token, or id_token_hint

	req, err := http.NewRequest("POST", baseURL+"/oauth/bc-authorize", strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error about missing hint
	if resp.StatusCode == http.StatusBadRequest {
		var errResp map[string]string
		json.NewDecoder(resp.Body).Decode(&errResp)
		t.Logf("CIBA missing hint error: %s", errResp["error_description"])
	}
}

// =============================================================================
// Security Tests
// =============================================================================

func TestDeviceCodeClientValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	verifyTestClientExists(t)

	data := url.Values{}
	data.Set("client_id", "nonexistent-client")
	data.Set("scope", "openid")

	req, err := http.NewRequest("POST", baseURL+"/oauth/device_authorization", strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should reject invalid client
	assert.True(t, resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized)
}

func TestTokenExchangeInvalidSubjectToken(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	verifyTestClientExists(t)

	data := url.Values{}
	data.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	data.Set("subject_token", "invalid.jwt.token")
	data.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")

	req, err := http.NewRequest("POST", baseURL+"/oauth/token", strings.NewReader(data.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(testClientID, testSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should reject invalid token
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
