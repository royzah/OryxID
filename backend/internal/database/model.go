package database

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Base model with common fields
type BaseModel struct {
	ID        uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// User represents a system user (admin)
type User struct {
	BaseModel
	Username string `gorm:"uniqueIndex;not null" json:"username"`
	Email    string `gorm:"uniqueIndex;not null" json:"email"`
	Password string `gorm:"not null" json:"-"`
	IsActive bool   `gorm:"default:true" json:"is_active"`
	IsAdmin  bool   `gorm:"default:false" json:"is_admin"`
	Roles    []Role `gorm:"many2many:user_roles;" json:"roles,omitempty"`
}

// Role represents user roles
type Role struct {
	BaseModel
	Name        string       `gorm:"uniqueIndex;not null" json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions,omitempty"`
	Users       []User       `gorm:"many2many:user_roles;" json:"-"`
}

// Permission represents fine-grained permissions
type Permission struct {
	BaseModel
	Name        string `gorm:"uniqueIndex;not null" json:"name"`
	Description string `json:"description"`
	Roles       []Role `gorm:"many2many:role_permissions;" json:"-"`
}

// Application represents an OAuth2 client
type Application struct {
	BaseModel
	Name                 string      `gorm:"not null" json:"name"`
	Description          string      `json:"description"`
	ClientID             string      `gorm:"uniqueIndex;not null" json:"client_id"`
	ClientSecret         string      `gorm:"not null" json:"-"`
	ClientType           string      `gorm:"not null;default:'confidential'" json:"client_type"` // confidential, public
	GrantTypes           StringArray `gorm:"type:text[]" json:"grant_types"`
	ResponseTypes        StringArray `gorm:"type:text[]" json:"response_types"`
	RedirectURIs         StringArray `gorm:"type:text[]" json:"redirect_uris"`
	PostLogoutURIs       StringArray `gorm:"type:text[]" json:"post_logout_uris"`
	Scopes               []Scope     `gorm:"many2many:application_scopes;" json:"scopes,omitempty"`
	Audiences            []Audience  `gorm:"many2many:application_audiences;" json:"audiences,omitempty"`
	SkipAuthorization    bool        `gorm:"default:false" json:"skip_authorization"`
	AccessTokenLifespan  int         `json:"access_token_lifespan"`  // seconds, 0 means use default
	RefreshTokenLifespan int         `json:"refresh_token_lifespan"` // seconds, 0 means use default
	Owner                *User       `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`
	OwnerID              *uuid.UUID  `json:"owner_id,omitempty"`
	Metadata             JSONB       `gorm:"type:jsonb" json:"metadata,omitempty"`
}

// Scope represents OAuth2 scopes
type Scope struct {
	BaseModel
	Name         string        `gorm:"uniqueIndex;not null" json:"name"`
	Description  string        `json:"description"`
	IsDefault    bool          `gorm:"default:false" json:"is_default"`
	Applications []Application `gorm:"many2many:application_scopes;" json:"-"`
}

// Audience represents API audiences
type Audience struct {
	BaseModel
	Identifier   string        `gorm:"uniqueIndex;not null" json:"identifier"`
	Name         string        `gorm:"not null" json:"name"`
	Description  string        `json:"description"`
	Scopes       []Scope       `gorm:"many2many:audience_scopes;" json:"scopes,omitempty"`
	Applications []Application `gorm:"many2many:application_audiences;" json:"-"`
}

// AuthorizationCode represents OAuth2 authorization codes
type AuthorizationCode struct {
	BaseModel
	Code                string      `gorm:"uniqueIndex;not null" json:"code"`
	ApplicationID       uuid.UUID   `gorm:"not null" json:"application_id"`
	Application         Application `gorm:"foreignKey:ApplicationID" json:"-"`
	UserID              *uuid.UUID  `json:"user_id,omitempty"`
	User                *User       `gorm:"foreignKey:UserID" json:"-"`
	RedirectURI         string      `json:"redirect_uri"`
	Scope               string      `json:"scope"`
	Audience            string      `json:"audience"`
	State               string      `json:"state"`
	Nonce               string      `json:"nonce"`
	CodeChallenge       string      `json:"code_challenge"`
	CodeChallengeMethod string      `json:"code_challenge_method"`
	ExpiresAt           time.Time   `json:"expires_at"`
	Used                bool        `gorm:"default:false" json:"used"`
}

// Token represents various token types (access, refresh)
type Token struct {
	BaseModel
	TokenHash     string      `gorm:"uniqueIndex;not null" json:"-"`
	TokenType     string      `gorm:"not null" json:"token_type"` // access, refresh
	ApplicationID uuid.UUID   `gorm:"not null" json:"application_id"`
	Application   Application `gorm:"foreignKey:ApplicationID" json:"-"`
	UserID        *uuid.UUID  `json:"user_id,omitempty"`
	User          *User       `gorm:"foreignKey:UserID" json:"-"`
	Scope         string      `json:"scope"`
	Audience      string      `json:"audience"`
	ExpiresAt     time.Time   `json:"expires_at"`
	Revoked       bool        `gorm:"default:false" json:"revoked"`
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
	Metadata      JSONB        `gorm:"type:jsonb" json:"metadata,omitempty"`
}

// StringArray is a custom type for PostgreSQL text[] support
type StringArray []string

func (s StringArray) Value() (driver.Value, error) {
	if len(s) == 0 {
		return "{}", nil
	}
	return s, nil
}

func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = []string{}
		return nil
	}
	// Handle the PostgreSQL array format
	// TODO: This is a simplified version - a full implementation would need more parsing
	*s = value.([]string)
	return nil
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
