// Package oryxid provides a client SDK for validating tokens issued by OryxID.
package oryxid

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// Client is the main OryxID SDK client.
type Client struct {
	issuer     string
	httpClient *http.Client

	// JWKS cache
	jwks     *JWKS
	jwksMu   sync.RWMutex
	jwksURL  string
	jwksTTL  time.Duration
	jwksLast time.Time

	// Introspection
	introspectURL string
	clientID      string
	clientSecret  string
}

// Config holds configuration for the OryxID client.
type Config struct {
	// IssuerURL is the base URL of the OryxID server (e.g., "https://auth.example.com")
	IssuerURL string

	// ClientID and ClientSecret for introspection endpoint (optional)
	ClientID     string
	ClientSecret string

	// JWKSCacheTTL is how long to cache the JWKS (default: 1 hour)
	JWKSCacheTTL time.Duration

	// HTTPClient allows custom HTTP client (optional)
	HTTPClient *http.Client
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// New creates a new OryxID client.
func New(cfg Config) (*Client, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("IssuerURL is required")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}

	ttl := cfg.JWKSCacheTTL
	if ttl == 0 {
		ttl = time.Hour
	}

	c := &Client{
		issuer:        cfg.IssuerURL,
		httpClient:    httpClient,
		jwksURL:       cfg.IssuerURL + "/.well-known/jwks.json",
		jwksTTL:       ttl,
		introspectURL: cfg.IssuerURL + "/oauth/introspect",
		clientID:      cfg.ClientID,
		clientSecret:  cfg.ClientSecret,
	}

	return c, nil
}

// GetPublicKey retrieves the RSA public key for the given key ID.
func (c *Client) GetPublicKey(kid string) (*rsa.PublicKey, error) {
	jwks, err := c.getJWKS()
	if err != nil {
		return nil, err
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid && key.Kty == "RSA" {
			return jwkToRSAPublicKey(&key)
		}
	}

	// Key not found, force refresh and try again
	c.jwksMu.Lock()
	c.jwksLast = time.Time{}
	c.jwksMu.Unlock()

	jwks, err = c.getJWKS()
	if err != nil {
		return nil, err
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid && key.Kty == "RSA" {
			return jwkToRSAPublicKey(&key)
		}
	}

	return nil, fmt.Errorf("key not found: %s", kid)
}

func (c *Client) getJWKS() (*JWKS, error) {
	c.jwksMu.RLock()
	if c.jwks != nil && time.Since(c.jwksLast) < c.jwksTTL {
		jwks := c.jwks
		c.jwksMu.RUnlock()
		return jwks, nil
	}
	c.jwksMu.RUnlock()

	c.jwksMu.Lock()
	defer c.jwksMu.Unlock()

	// Double-check after acquiring write lock
	if c.jwks != nil && time.Since(c.jwksLast) < c.jwksTTL {
		return c.jwks, nil
	}

	resp, err := c.httpClient.Get(c.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS fetch failed with status: %d", resp.StatusCode)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	c.jwks = &jwks
	c.jwksLast = time.Now()

	return &jwks, nil
}

func jwkToRSAPublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	// Decode N (modulus)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		// Try standard base64
		nBytes, err = base64.StdEncoding.DecodeString(jwk.N)
		if err != nil {
			return nil, fmt.Errorf("failed to decode modulus: %w", err)
		}
	}
	n := new(big.Int).SetBytes(nBytes)

	// Decode E (exponent)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		// Try standard base64
		eBytes, err = base64.StdEncoding.DecodeString(jwk.E)
		if err != nil {
			return nil, fmt.Errorf("failed to decode exponent: %w", err)
		}
	}
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
