package database

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// StringArray is a custom type for storing string arrays as JSONB in PostgreSQL
// This provides full GORM compatibility while maintaining array functionality
type StringArray []string

// Scan implements the sql.Scanner interface for JSONB deserialization
func (a *StringArray) Scan(value interface{}) error {
	if value == nil {
		*a = []string{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return nil
	}

	return json.Unmarshal(bytes, a)
}

// Value implements the driver.Valuer interface for JSONB serialization
func (a StringArray) Value() (driver.Value, error) {
	if len(a) == 0 {
		return json.Marshal([]string{})
	}
	return json.Marshal(a)
}

// Base model with common fields
type BaseModel struct {
	ID        uuid.UUID      `gorm:"primaryKey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// BeforeCreate hook to generate UUID before creating record
func (b *BaseModel) BeforeCreate(tx *gorm.DB) error {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	return nil
}

// User represents a system user (admin)
type User struct {
	BaseModel
	Username      string `gorm:"uniqueIndex;not null" json:"username"`
	Email         string `gorm:"uniqueIndex;not null" json:"email"`
	EmailVerified bool   `gorm:"default:false" json:"email_verified"`
	Password      string `gorm:"not null" json:"-"`
	IsActive      bool   `gorm:"default:true" json:"is_active"`
	IsAdmin       bool   `gorm:"default:false" json:"is_admin"`
	Roles         []Role `gorm:"many2many:user_roles" json:"roles,omitempty"`
}

// Role represents user roles
type Role struct {
	BaseModel
	Name        string       `gorm:"uniqueIndex;not null" json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `gorm:"many2many:role_permissions" json:"permissions,omitempty"`
	Users       []User       `gorm:"many2many:user_roles" json:"-"`
}

// Permission represents fine-grained permissions
type Permission struct {
	BaseModel
	Name        string `gorm:"uniqueIndex;not null" json:"name"`
	Description string `json:"description"`
	Roles       []Role `gorm:"many2many:role_permissions" json:"-"`
}

// Application represents an OAuth2 client
type Application struct {
	BaseModel
	Name                    string      `gorm:"not null" json:"name"`
	Description             string      `json:"description"`
	ClientID                string      `gorm:"uniqueIndex;not null" json:"client_id"`
	HashedClientSecret      string      `gorm:"not null" json:"-"`           // Only store hashed secret
	ClientType              string      `gorm:"not null" json:"client_type"` // confidential, public
	TokenEndpointAuthMethod string      `json:"token_endpoint_auth_method"`  // client_secret_basic, client_secret_post, private_key_jwt
	PublicKeyPEM            string      `json:"public_key_pem,omitempty"`    // For private_key_jwt authentication
	JWKSURI                 string      `json:"jwks_uri,omitempty"`          // Alternative to PublicKeyPEM - fetch keys from URL
	GrantTypes              StringArray `gorm:"type:jsonb" json:"grant_types"`
	ResponseTypes           StringArray `gorm:"type:jsonb" json:"response_types"`
	RedirectURIs            StringArray `gorm:"type:jsonb" json:"redirect_uris"`
	PostLogoutURIs          StringArray `gorm:"type:jsonb" json:"post_logout_uris"`
	Scopes                  []Scope     `gorm:"many2many:application_scopes" json:"scopes,omitempty"`
	Audiences               []Audience  `gorm:"many2many:application_audiences" json:"audiences,omitempty"`
	SkipAuthorization       bool        `gorm:"default:false" json:"skip_authorization"`
	AccessTokenLifespan     int         `json:"access_token_lifespan"`  // seconds, 0 means use default
	RefreshTokenLifespan    int         `json:"refresh_token_lifespan"` // seconds, 0 means use default
	Owner                   *User       `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`
	OwnerID                 *uuid.UUID  `json:"owner_id,omitempty"`
	Metadata                JSONB       `gorm:"type:jsonb" json:"metadata,omitempty"`
}

// Scope represents OAuth2 scopes
type Scope struct {
	BaseModel
	Name         string        `gorm:"uniqueIndex;not null" json:"name"`
	Description  string        `json:"description"`
	IsDefault    bool          `gorm:"default:false" json:"is_default"`
	Applications []Application `gorm:"many2many:application_scopes" json:"-"`
}

// Audience represents API audiences
type Audience struct {
	BaseModel
	Identifier   string        `gorm:"uniqueIndex;not null" json:"identifier"`
	Name         string        `gorm:"not null" json:"name"`
	Description  string        `json:"description"`
	Scopes       []Scope       `gorm:"many2many:audience_scopes" json:"scopes,omitempty"`
	Applications []Application `gorm:"many2many:application_audiences" json:"-"`
}

// AuthorizationCode represents OAuth2 authorization codes
type AuthorizationCode struct {
	BaseModel
	Code                 string      `gorm:"uniqueIndex;not null" json:"code"`
	ApplicationID        uuid.UUID   `gorm:"not null" json:"application_id"`
	Application          Application `gorm:"foreignKey:ApplicationID" json:"-"`
	UserID               *uuid.UUID  `json:"user_id,omitempty"`
	User                 *User       `gorm:"foreignKey:UserID" json:"-"`
	RedirectURI          string      `json:"redirect_uri"`
	Scope                string      `json:"scope"`
	Audience             string      `json:"audience"`
	AuthorizationDetails string      `json:"authorization_details,omitempty"` // RAR (RFC 9396) - JSON array of authorization details
	State                string      `json:"state"`
	Nonce                string      `json:"nonce"`
	CodeChallenge        string      `json:"code_challenge"`
	CodeChallengeMethod  string      `json:"code_challenge_method"`
	ExpiresAt            time.Time   `json:"expires_at"`
	Used                 bool        `gorm:"default:false" json:"used"`
}

// Token represents various token types (access, refresh)
type Token struct {
	BaseModel
	TokenHash            string      `gorm:"uniqueIndex;not null" json:"-"`
	TokenType            string      `gorm:"not null" json:"token_type"` // access, refresh
	ApplicationID        uuid.UUID   `gorm:"not null" json:"application_id"`
	Application          Application `gorm:"foreignKey:ApplicationID" json:"-"`
	UserID               *uuid.UUID  `json:"user_id,omitempty"`
	User                 *User       `gorm:"foreignKey:UserID" json:"-"`
	Scope                string      `json:"scope"`
	Audience             string      `json:"audience"`
	AuthorizationDetails string      `json:"authorization_details,omitempty"` // RAR (RFC 9396)
	ExpiresAt            time.Time   `json:"expires_at"`
	Revoked              bool        `gorm:"default:false" json:"revoked"`
	RevokedAt            *time.Time  `json:"revoked_at,omitempty"`
}

// Session represents user sessions
type Session struct {
	BaseModel
	SessionID string    `gorm:"uniqueIndex;not null" json:"session_id"`
	UserID    uuid.UUID `gorm:"not null" json:"user_id"`
	User      User      `gorm:"foreignKey:UserID" json:"-"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	ExpiresAt time.Time `json:"expires_at"`
	LastUsed  time.Time `json:"last_used"`
}

// AuditLog represents audit trail
type AuditLog struct {
	BaseModel
	UserID        *uuid.UUID   `json:"user_id,omitempty"`
	User          *User        `gorm:"foreignKey:UserID" json:"-"`
	ApplicationID *uuid.UUID   `json:"application_id,omitempty"`
	Application   *Application `gorm:"foreignKey:ApplicationID" json:"-"`
	Action        string       `gorm:"not null" json:"action"`
	Resource      string       `json:"resource"`
	ResourceID    string       `json:"resource_id"`
	IPAddress     string       `json:"ip_address"`
	UserAgent     string       `json:"user_agent"`
	StatusCode    int          `json:"status_code"`
	Metadata      JSONB        `gorm:"type:jsonb" json:"metadata,omitempty"`
}

// JSONB is a custom type for PostgreSQL JSONB support
type JSONB map[string]interface{}

func (j JSONB) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return json.Marshal(j)
}

func (j *JSONB) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("failed to scan JSONB")
	}
	return json.Unmarshal(bytes, j)
}

// SigningKey represents a cryptographic key for JWT signing (key rotation support)
type SigningKey struct {
	BaseModel
	KeyID         string     `gorm:"uniqueIndex;not null" json:"key_id"`  // kid claim
	Algorithm     string     `gorm:"not null" json:"algorithm"`           // Signing algorithm
	PrivateKeyPEM string     `gorm:"not null" json:"-"`                   // PEM-encoded private key (never exposed)
	PublicKeyPEM  string     `gorm:"not null" json:"public_key_pem"`      // PEM-encoded public key
	IsActive      bool       `gorm:"default:true;index" json:"is_active"` // Currently used for signing
	ActivatedAt   time.Time  `gorm:"not null" json:"activated_at"`        // When this key became active
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`                // Optional expiration (for key rotation)
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`                // If key compromised
}

// CIBAAuthenticationRequest represents a CIBA authentication request (OpenID Connect CIBA)
type CIBAAuthenticationRequest struct {
	BaseModel
	AuthReqID         string      `gorm:"uniqueIndex;not null" json:"auth_req_id"` // Unique authentication request ID
	ApplicationID     uuid.UUID   `gorm:"not null;index" json:"application_id"`
	Application       Application `gorm:"foreignKey:ApplicationID" json:"-"`
	UserID            *uuid.UUID  `json:"user_id,omitempty"`                     // User being authenticated
	User              *User       `gorm:"foreignKey:UserID" json:"-"`            // The user
	BindingMessage    string      `json:"binding_message,omitempty"`             // Message shown to user
	ClientNotifyToken string      `json:"client_notify_token,omitempty"`         // Token for callback notification
	Scope             string      `json:"scope,omitempty"`                        // Requested scopes
	ACRValues         string      `json:"acr_values,omitempty"`                   // Requested authentication context
	LoginHint         string      `json:"login_hint,omitempty"`                   // Hint to identify user
	LoginHintToken    string      `json:"login_hint_token,omitempty"`             // JWT containing user hint
	IDTokenHint       string      `json:"id_token_hint,omitempty"`                // Previous ID token as hint
	RequestedExpiry   int         `json:"requested_expiry,omitempty"`             // Requested auth expiry
	ExpiresAt         time.Time   `gorm:"not null;index" json:"expires_at"`       // When the request expires
	Interval          int         `gorm:"default:5" json:"interval"`              // Polling interval in seconds
	Status            string      `gorm:"default:'pending';index" json:"status"`  // pending, authorized, denied, expired
	AuthorizedAt      *time.Time  `json:"authorized_at,omitempty"`                // When user authorized
	LastPollAt        *time.Time  `json:"last_poll_at,omitempty"`                 // Last time client polled
}

// DeviceCode represents a device authorization request (RFC 8628)
type DeviceCode struct {
	BaseModel
	DeviceCode       string      `gorm:"uniqueIndex;not null" json:"device_code"`    // Secret code for device
	UserCode         string      `gorm:"uniqueIndex;not null" json:"user_code"`      // Code displayed to user (e.g., "WDJB-MJHT")
	ApplicationID    uuid.UUID   `gorm:"not null;index" json:"application_id"`       // Which app requested this
	Application      Application `gorm:"foreignKey:ApplicationID" json:"-"`          // The application
	UserID           *uuid.UUID  `json:"user_id,omitempty"`                          // User who authorized (set after authorization)
	User             *User       `gorm:"foreignKey:UserID" json:"-"`                 // The authorizing user
	Scope            string      `json:"scope,omitempty"`                            // Requested scopes
	Audience         string      `json:"audience,omitempty"`                         // Target audience
	VerificationURI  string      `json:"verification_uri"`                           // Where user should go to authorize
	ExpiresAt        time.Time   `gorm:"not null;index" json:"expires_at"`           // When the codes expire
	Interval         int         `gorm:"default:5" json:"interval"`                  // Polling interval in seconds
	Status           string      `gorm:"default:'pending';index" json:"status"`      // pending, authorized, denied, expired
	AuthorizedAt     *time.Time  `json:"authorized_at,omitempty"`                    // When user authorized
	LastPollAt       *time.Time  `json:"last_poll_at,omitempty"`                     // Last time device polled
	ClientIP         string      `json:"client_ip,omitempty"`                        // Device IP address
}

// PushedAuthorizationRequest represents a PAR object (RFC 9126)
type PushedAuthorizationRequest struct {
	BaseModel
	RequestURI           string    `gorm:"uniqueIndex;not null" json:"request_uri"` // urn:ietf:params:oauth:request_uri:<value>
	ApplicationID        uuid.UUID `gorm:"not null;index" json:"application_id"`
	ResponseType         string    `gorm:"not null" json:"response_type"`
	ClientID             string    `gorm:"not null" json:"client_id"`
	RedirectURI          string    `gorm:"not null" json:"redirect_uri"`
	Scope                string    `json:"scope,omitempty"`
	State                string    `json:"state,omitempty"`
	Nonce                string    `json:"nonce,omitempty"`
	CodeChallenge        string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod  string    `json:"code_challenge_method,omitempty"`
	AuthorizationDetails string    `json:"authorization_details,omitempty"` // RAR (RFC 9396) - JSON array of authorization details
	ExpiresAt            time.Time `gorm:"not null;index" json:"expires_at"` // PAR requests expire quickly (typically 90 seconds)
	Used                 bool      `gorm:"default:false;index" json:"used"`  // One-time use
}

// ServerSettings represents OAuth2/OIDC server configuration (singleton)
type ServerSettings struct {
	BaseModel
	Key   string `gorm:"uniqueIndex;not null" json:"key"` // Always "default" for singleton
	Value JSONB  `gorm:"type:jsonb" json:"value"`
}

// ServerSettingsData is the structure stored in ServerSettings.Value
type ServerSettingsData struct {
	Issuer                  string `json:"issuer"`
	AccessTokenLifespan     int    `json:"access_token_lifespan"`     // seconds
	RefreshTokenLifespan    int    `json:"refresh_token_lifespan"`    // seconds
	IDTokenLifespan         int    `json:"id_token_lifespan"`         // seconds
	AuthCodeLifespan        int    `json:"auth_code_lifespan"`        // seconds
	RequirePKCE             bool   `json:"require_pkce"`
	AllowImplicit           bool   `json:"allow_implicit"`
	RotateRefreshTokens     bool   `json:"rotate_refresh_tokens"`
	RevokeOldRefreshTokens  bool   `json:"revoke_old_refresh_tokens"`
}
