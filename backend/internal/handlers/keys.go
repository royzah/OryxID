package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/pkg/crypto"
	"gorm.io/gorm"
)

type KeyManagementHandler struct {
	db *gorm.DB
}

func NewKeyManagementHandler(db *gorm.DB) *KeyManagementHandler {
	return &KeyManagementHandler{
		db: db,
	}
}

type RotateKeyRequest struct {
	Algorithm     string `json:"algorithm" binding:"required,oneof=RS256 RS384 RS512"`
	ExpiresInDays int    `json:"expires_in_days" binding:"required,min=1,max=365"`
}

type KeyResponse struct {
	ID        string    `json:"id"`
	Kid       string    `json:"kid"`
	Algorithm string    `json:"algorithm"`
	KeyType   string    `json:"key_type"`
	Use       string    `json:"use"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

type RotateKeyResponse struct {
	Message string      `json:"message"`
	Key     KeyResponse `json:"key"`
}

// RotateKey generates a new signing key and marks it as active
// POST /api/v1/keys/rotate
func (h *KeyManagementHandler) RotateKey(c *gin.Context) {
	var req RotateKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": err.Error(),
		})
		return
	}

	// Generate new RSA key pair based on algorithm
	keySize := 4096 // Default to 4096 for RS256
	switch req.Algorithm {
	case "RS256":
		keySize = 4096
	case "RS384":
		keySize = 4096
	case "RS512":
		keySize = 4096
	}

	privateKey, err := crypto.GenerateRSAKeyPair(keySize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to generate key pair",
		})
		return
	}

	// Convert keys to PEM format for storage
	privateKeyPEM, err := crypto.PrivateKeyToPEM(privateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to encode private key",
		})
		return
	}

	publicKeyPEM, err := crypto.PublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to encode public key",
		})
		return
	}

	// Generate unique key ID
	kid := uuid.New().String()

	// Calculate expiration
	expiresAt := time.Now().AddDate(0, 0, req.ExpiresInDays)

	// Create signing key record
	signingKey := &database.SigningKey{
		Kid:           kid,
		Algorithm:     req.Algorithm,
		KeyType:       "RSA",
		Use:           "sig",
		PrivateKey:    string(privateKeyPEM),
		PublicKey:     string(publicKeyPEM),
		Active:        true,
		ExpiresAt:     expiresAt,
	}

	// Start transaction
	tx := h.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Optional: Mark old keys as inactive (gradual rollover)
	// Uncomment the following to immediately deactivate old keys
	// if err := tx.Model(&database.SigningKey{}).Where("active = ?", true).Update("active", false).Error; err != nil {
	// 	tx.Rollback()
	// 	c.JSON(http.StatusInternalServerError, gin.H{
	// 		"error": "server_error",
	// 		"error_description": "Failed to deactivate old keys",
	// 	})
	// 	return
	// }

	// Save new key
	if err := tx.Create(signingKey).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to save signing key",
		})
		return
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to commit transaction",
		})
		return
	}

	// Log the key rotation
	h.logAudit(c, "keys.rotate", "key", signingKey.ID.String())

	c.JSON(http.StatusCreated, RotateKeyResponse{
		Message: "Key rotated successfully. New key is now active for signing. Old keys remain valid for verification.",
		Key: KeyResponse{
			ID:        signingKey.ID.String(),
			Kid:       signingKey.Kid,
			Algorithm: signingKey.Algorithm,
			KeyType:   signingKey.KeyType,
			Use:       signingKey.Use,
			Active:    signingKey.Active,
			CreatedAt: signingKey.CreatedAt,
			ExpiresAt: signingKey.ExpiresAt,
		},
	})
}

// ListKeys returns all signing keys (active and revoked)
// GET /api/v1/keys
func (h *KeyManagementHandler) ListKeys(c *gin.Context) {
	var keys []database.SigningKey

	query := h.db.Order("created_at DESC")

	// Optional filters
	if activeOnly := c.Query("active_only"); activeOnly == "true" {
		query = query.Where("active = ? AND revoked_at IS NULL", true)
	}

	if err := query.Find(&keys).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
		})
		return
	}

	response := make([]KeyResponse, len(keys))
	for i, key := range keys {
		response[i] = KeyResponse{
			ID:        key.ID.String(),
			Kid:       key.Kid,
			Algorithm: key.Algorithm,
			KeyType:   key.KeyType,
			Use:       key.Use,
			Active:    key.Active,
			CreatedAt: key.CreatedAt,
			ExpiresAt: key.ExpiresAt,
			RevokedAt: key.RevokedAt,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"keys": response,
	})
}

// GetKey returns details of a specific signing key
// GET /api/v1/keys/:kid
func (h *KeyManagementHandler) GetKey(c *gin.Context) {
	kid := c.Param("kid")

	var key database.SigningKey
	if err := h.db.Where("kid = ?", kid).First(&key).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "key_not_found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
		})
		return
	}

	c.JSON(http.StatusOK, KeyResponse{
		ID:        key.ID.String(),
		Kid:       key.Kid,
		Algorithm: key.Algorithm,
		KeyType:   key.KeyType,
		Use:       key.Use,
		Active:    key.Active,
		CreatedAt: key.CreatedAt,
		ExpiresAt: key.ExpiresAt,
		RevokedAt: key.RevokedAt,
	})
}

// RevokeKey revokes a signing key (e.g., if compromised)
// POST /api/v1/keys/:kid/revoke
func (h *KeyManagementHandler) RevokeKey(c *gin.Context) {
	kid := c.Param("kid")

	var key database.SigningKey
	if err := h.db.Where("kid = ?", kid).First(&key).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "key_not_found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
		})
		return
	}

	// Check if key is already revoked
	if key.RevokedAt != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "already_revoked",
			"error_description": "Key is already revoked",
		})
		return
	}

	// Revoke the key
	now := time.Now()
	if err := h.db.Model(&key).Updates(map[string]interface{}{
		"active":     false,
		"revoked_at": now,
	}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to revoke key",
		})
		return
	}

	// Log the revocation
	h.logAudit(c, "keys.revoke", "key", key.ID.String())

	c.JSON(http.StatusOK, gin.H{
		"message":    "Key revoked successfully",
		"kid":        kid,
		"revoked_at": now,
	})
}

// DeactivateKey marks a key as inactive without revoking it
// POST /api/v1/keys/:kid/deactivate
func (h *KeyManagementHandler) DeactivateKey(c *gin.Context) {
	kid := c.Param("kid")

	var key database.SigningKey
	if err := h.db.Where("kid = ?", kid).First(&key).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "key_not_found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
		})
		return
	}

	// Deactivate the key (but don't revoke)
	if err := h.db.Model(&key).Update("active", false).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to deactivate key",
		})
		return
	}

	// Log the deactivation
	h.logAudit(c, "keys.deactivate", "key", key.ID.String())

	c.JSON(http.StatusOK, gin.H{
		"message": "Key deactivated successfully. It can still verify existing tokens but won't sign new ones.",
		"kid":     kid,
	})
}

// ActivateKey marks a key as active again
// POST /api/v1/keys/:kid/activate
func (h *KeyManagementHandler) ActivateKey(c *gin.Context) {
	kid := c.Param("kid")

	var key database.SigningKey
	if err := h.db.Where("kid = ?", kid).First(&key).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "key_not_found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "server_error",
		})
		return
	}

	// Check if key is revoked
	if key.RevokedAt != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "key_revoked",
			"error_description": "Cannot activate a revoked key",
		})
		return
	}

	// Check if key is expired
	if time.Now().After(key.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "key_expired",
			"error_description": "Cannot activate an expired key",
		})
		return
	}

	// Activate the key
	if err := h.db.Model(&key).Update("active", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to activate key",
		})
		return
	}

	// Log the activation
	h.logAudit(c, "keys.activate", "key", key.ID.String())

	c.JSON(http.StatusOK, gin.H{
		"message": "Key activated successfully",
		"kid":     kid,
	})
}

// CleanupExpiredKeys removes expired keys from the database
// POST /api/v1/keys/cleanup
func (h *KeyManagementHandler) CleanupExpiredKeys(c *gin.Context) {
	// Only delete keys that are expired AND revoked
	result := h.db.Where("expires_at < ? AND revoked_at IS NOT NULL", time.Now()).Delete(&database.SigningKey{})

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":             "server_error",
			"error_description": "Failed to cleanup keys",
		})
		return
	}

	// Log the cleanup
	h.logAudit(c, "keys.cleanup", "keys", "expired")

	c.JSON(http.StatusOK, gin.H{
		"message":       "Expired keys cleaned up successfully",
		"deleted_count": result.RowsAffected,
	})
}

// Helper function to log audit events
func (h *KeyManagementHandler) logAudit(c *gin.Context, action, resource, resourceID string) {
	// Extract user ID from context (set by auth middleware)
	userID := c.GetString("user_id")

	audit := database.AuditLog{
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
	}

	if userID != "" {
		if id, err := uuid.Parse(userID); err == nil {
			audit.UserID = &id
		}
	}

	// Don't block the request if audit logging fails
	if err := h.db.Create(&audit).Error; err != nil {
		// Log error but continue
		c.Error(err)
	}
}
