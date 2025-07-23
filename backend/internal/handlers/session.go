package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/redis"
	"gorm.io/gorm"
)

type SessionHandler struct {
	db    *gorm.DB
	redis *redis.Client
}

func NewSessionHandler(db *gorm.DB, redis *redis.Client) *SessionHandler {
	return &SessionHandler{
		db:    db,
		redis: redis,
	}
}

// ListSessions returns all active sessions for the current user
func (h *SessionHandler) ListSessions(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	var sessions []database.Session
	if err := h.db.Where("user_id = ? AND expires_at > ?", userID, time.Now()).
		Order("last_used DESC").
		Find(&sessions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch sessions"})
		return
	}

	// Enrich session data with current session indicator
	currentSessionID := c.GetString("session_id")
	response := make([]gin.H, len(sessions))

	for i, session := range sessions {
		response[i] = gin.H{
			"id":         session.ID,
			"session_id": session.SessionID,
			"ip_address": session.IPAddress,
			"user_agent": session.UserAgent,
			"created_at": session.CreatedAt,
			"last_used":  session.LastUsed,
			"expires_at": session.ExpiresAt,
			"is_current": session.SessionID == currentSessionID,
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": response,
		"total":    len(sessions),
	})
}

// RevokeSession revokes a specific session
func (h *SessionHandler) RevokeSession(c *gin.Context) {
	sessionID := c.Param("id")
	userID := c.GetString("user_id")

	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Parse session ID
	sid, err := uuid.Parse(sessionID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid session ID"})
		return
	}

	// Find session
	var session database.Session
	if err := h.db.Where("id = ? AND user_id = ?", sid, userID).First(&session).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find session"})
		return
	}

	// Check if trying to revoke current session
	currentSessionID := c.GetString("session_id")
	if session.SessionID == currentSessionID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot revoke current session. Use logout instead."})
		return
	}

	// Delete session from database
	if err := h.db.Delete(&session).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke session"})
		return
	}

	// Delete from Redis if available
	if h.redis != nil {
		if err := h.redis.DeleteSession(session.SessionID); err != nil {
			// Log error but don't fail the request
			c.Error(err)
		}
	}

	// Log audit event
	h.logAudit(c, "session.revoke", "session", session.ID.String())

	c.JSON(http.StatusOK, gin.H{"message": "Session revoked successfully"})
}

// RevokeAllSessions revokes all sessions except the current one
func (h *SessionHandler) RevokeAllSessions(c *gin.Context) {
	userID := c.GetString("user_id")
	currentSessionID := c.GetString("session_id")

	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Get all sessions to revoke
	var sessions []database.Session
	if err := h.db.Where("user_id = ? AND session_id != ?", userID, currentSessionID).
		Find(&sessions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch sessions"})
		return
	}

	// Delete all sessions except current from database
	result := h.db.Where("user_id = ? AND session_id != ?", userID, currentSessionID).
		Delete(&database.Session{})

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to revoke sessions"})
		return
	}

	// Delete from Redis if available
	if h.redis != nil {
		for _, session := range sessions {
			if err := h.redis.DeleteSession(session.SessionID); err != nil {
				// Log error but don't fail the request
				c.Error(err)
			}
		}
	}

	// Log audit event
	h.logAudit(c, "session.revoke_all", "session", userID)

	c.JSON(http.StatusOK, gin.H{
		"message": "All other sessions revoked successfully",
		"revoked": result.RowsAffected,
	})
}

// GetActiveSessionsCount returns the count of active sessions for a user
func (h *SessionHandler) GetActiveSessionsCount(userID string) (int64, error) {
	var count int64
	err := h.db.Model(&database.Session{}).
		Where("user_id = ? AND expires_at > ?", userID, time.Now()).
		Count(&count).Error
	return count, err
}

// CleanupExpiredSessions removes expired sessions from the database
func (h *SessionHandler) CleanupExpiredSessions() error {
	result := h.db.Where("expires_at < ?", time.Now()).Delete(&database.Session{})
	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected > 0 {
		// Log cleanup
		audit := database.AuditLog{
			Action:   "session.cleanup",
			Resource: "session",
			Metadata: database.JSONB{
				"deleted_count": result.RowsAffected,
			},
		}
		h.db.Create(&audit)
	}

	return nil
}

// UpdateSessionActivity updates the last used timestamp of a session
func (h *SessionHandler) UpdateSessionActivity(sessionID string) error {
	return h.db.Model(&database.Session{}).
		Where("session_id = ?", sessionID).
		Update("last_used", time.Now()).Error
}

// CreateSession creates a new session
func (h *SessionHandler) CreateSession(userID uuid.UUID, ipAddress, userAgent string, duration time.Duration) (*database.Session, error) {
	sessionID := uuid.New().String()

	session := &database.Session{
		SessionID: sessionID,
		UserID:    userID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		ExpiresAt: time.Now().Add(duration),
		LastUsed:  time.Now(),
	}

	if err := h.db.Create(session).Error; err != nil {
		return nil, err
	}

	// Store in Redis if available
	if h.redis != nil {
		sessionData := map[string]interface{}{
			"user_id":    userID.String(),
			"ip_address": ipAddress,
			"user_agent": userAgent,
			"created_at": session.CreatedAt,
		}

		if err := h.redis.SetSession(sessionID, sessionData, duration); err != nil {
			// Log error but don't fail session creation
			// Redis is optional for session storage
			_ = err
		}
	}

	return session, nil
}

// ValidateSession checks if a session is valid
func (h *SessionHandler) ValidateSession(sessionID string) (*database.Session, error) {
	// Try Redis first if available
	if h.redis != nil {
		var sessionData map[string]interface{}
		if err := h.redis.GetSession(sessionID, &sessionData); err == nil {
			// Session found in Redis, validate against database
			var session database.Session
			if err := h.db.Where("session_id = ? AND expires_at > ?", sessionID, time.Now()).
				First(&session).Error; err == nil {
				// Update last used
				go h.UpdateSessionActivity(sessionID)
				return &session, nil
			}
		}
	}

	// Fallback to database
	var session database.Session
	if err := h.db.Where("session_id = ? AND expires_at > ?", sessionID, time.Now()).
		First(&session).Error; err != nil {
		return nil, err
	}

	// Update last used
	go h.UpdateSessionActivity(sessionID)

	return &session, nil
}

// Helper function to log audit events
func (h *SessionHandler) logAudit(c *gin.Context, action, resource, resourceID string) {
	audit := database.AuditLog{
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
		StatusCode: c.Writer.Status(),
		Metadata: database.JSONB{
			"method": c.Request.Method,
			"path":   c.Request.URL.Path,
		},
	}

	// Get user ID from context
	if userID := c.GetString("user_id"); userID != "" {
		if uid, err := uuid.Parse(userID); err == nil {
			audit.UserID = &uid
		}
	}

	h.db.Create(&audit)
}
