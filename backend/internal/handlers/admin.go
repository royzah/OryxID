package handlers

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/tokens"
	"github.com/tiiuae/oryxid/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AdminHandler struct {
	db           *gorm.DB
	tokenManager *tokens.TokenManager
}

func NewAdminHandler(db *gorm.DB, tm *tokens.TokenManager) *AdminHandler {
	return &AdminHandler{
		db:           db,
		tokenManager: tm,
	}
}

// Application Handlers

func (h *AdminHandler) ListApplications(c *gin.Context) {
	var apps []database.Application
	query := h.db.Preload("Scopes").Preload("Audiences")

	// Optional filtering
	if search := c.Query("search"); search != "" {
		query = query.Where("name ILIKE ? OR client_id ILIKE ?", "%"+search+"%", "%"+search+"%")
	}

	if err := query.Find(&apps).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch applications"})
		return
	}

	c.JSON(http.StatusOK, apps)
}

func (h *AdminHandler) CreateApplication(c *gin.Context) {
	var req struct {
		Name              string   `json:"name" binding:"required"`
		Description       string   `json:"description"`
		ClientType        string   `json:"client_type" binding:"required,oneof=confidential public"`
		GrantTypes        []string `json:"grant_types" binding:"required,min=1"`
		ResponseTypes     []string `json:"response_types"`
		RedirectURIs      []string `json:"redirect_uris" binding:"required,min=1"`
		PostLogoutURIs    []string `json:"post_logout_uris"`
		ScopeIDs          []string `json:"scope_ids"`
		AudienceIDs       []string `json:"audience_ids"`
		SkipAuthorization bool     `json:"skip_authorization"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate client credentials
	clientID, err := crypto.GenerateSecureToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate client ID"})
		return
	}

	var clientSecret string
	var hashedSecret string

	// Only generate secret for confidential clients
	if req.ClientType == "confidential" {
		clientSecret, err = crypto.GenerateSecureToken(64)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate client secret"})
			return
		}

		// Hash client secret for storage
		hashedSecretBytes, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash client secret"})
			return
		}
		hashedSecret = string(hashedSecretBytes)
	}

	app := database.Application{
		Name:               req.Name,
		Description:        req.Description,
		ClientID:           clientID,
		HashedClientSecret: hashedSecret,
		ClientType:         req.ClientType,
		GrantTypes:         database.StringArray(req.GrantTypes),
		ResponseTypes:      database.StringArray(req.ResponseTypes),
		RedirectURIs:       database.StringArray(req.RedirectURIs),
		PostLogoutURIs:     database.StringArray(req.PostLogoutURIs),
		SkipAuthorization:  req.SkipAuthorization,
	}

	// Get current user ID
	if userID := c.GetString("user_id"); userID != "" {
		if uid, err := uuid.Parse(userID); err == nil {
			app.OwnerID = &uid
		}
	}

	// Start transaction
	tx := h.db.Begin()

	if err := tx.Create(&app).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create application"})
		return
	}

	// Assign scopes if provided
	if len(req.ScopeIDs) > 0 {
		var scopes []database.Scope
		if err := tx.Where("id IN ?", req.ScopeIDs).Find(&scopes).Error; err == nil && len(scopes) > 0 {
			if err := tx.Model(&app).Association("Scopes").Replace(scopes); err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign scopes"})
				return
			}
		}
	}

	// Assign audiences if provided
	if len(req.AudienceIDs) > 0 {
		var audiences []database.Audience
		if err := tx.Where("id IN ?", req.AudienceIDs).Find(&audiences).Error; err == nil && len(audiences) > 0 {
			if err := tx.Model(&app).Association("Audiences").Replace(audiences); err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign audiences"})
				return
			}
		}
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// Log audit event
	h.logAudit(c, "application.create", "application", app.ID.String(), http.StatusCreated)

	// Reload with associations
	h.db.Preload("Scopes").Preload("Audiences").First(&app, app.ID)

	// Build response
	response := gin.H{
		"id":                 app.ID,
		"name":               app.Name,
		"description":        app.Description,
		"client_id":          app.ClientID,
		"client_type":        app.ClientType,
		"grant_types":        app.GrantTypes,
		"response_types":     app.ResponseTypes,
		"redirect_uris":      app.RedirectURIs,
		"post_logout_uris":   app.PostLogoutURIs,
		"scopes":             app.Scopes,
		"audiences":          app.Audiences,
		"skip_authorization": app.SkipAuthorization,
		"created_at":         app.CreatedAt,
	}

	// Include client secret only for confidential clients on creation
	if req.ClientType == "confidential" && clientSecret != "" {
		response["client_secret"] = clientSecret
	}

	c.JSON(http.StatusCreated, response)
}

func (h *AdminHandler) GetApplication(c *gin.Context) {
	id := c.Param("id")

	var app database.Application
	if err := h.db.Preload("Scopes").Preload("Audiences").Where("id = ?", id).First(&app).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch application"})
		return
	}

	c.JSON(http.StatusOK, app)
}

func (h *AdminHandler) UpdateApplication(c *gin.Context) {
	id := c.Param("id")

	var app database.Application
	if err := h.db.Where("id = ?", id).First(&app).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Application not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch application"})
		return
	}

	var req struct {
		Name              string   `json:"name"`
		Description       string   `json:"description"`
		RedirectURIs      []string `json:"redirect_uris"`
		PostLogoutURIs    []string `json:"post_logout_uris"`
		ScopeIDs          []string `json:"scope_ids"`
		AudienceIDs       []string `json:"audience_ids"`
		SkipAuthorization *bool    `json:"skip_authorization"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update fields
	if req.Name != "" {
		app.Name = req.Name
	}
	app.Description = req.Description
	if len(req.RedirectURIs) > 0 {
		app.RedirectURIs = req.RedirectURIs
	}
	if req.PostLogoutURIs != nil {
		app.PostLogoutURIs = req.PostLogoutURIs
	}
	if req.SkipAuthorization != nil {
		app.SkipAuthorization = *req.SkipAuthorization
	}

	tx := h.db.Begin()

	if err := tx.Save(&app).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update application"})
		return
	}

	// Update scopes
	if req.ScopeIDs != nil {
		var scopes []database.Scope
		if len(req.ScopeIDs) > 0 {
			tx.Where("id IN ?", req.ScopeIDs).Find(&scopes)
		}
		if err := tx.Model(&app).Association("Scopes").Replace(scopes); err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update scopes"})
			return
		}
	}

	// Update audiences
	if req.AudienceIDs != nil {
		var audiences []database.Audience
		if len(req.AudienceIDs) > 0 {
			tx.Where("id IN ?", req.AudienceIDs).Find(&audiences)
		}
		if err := tx.Model(&app).Association("Audiences").Replace(audiences); err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update audiences"})
			return
		}
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// Log audit event
	h.logAudit(c, "application.update", "application", app.ID.String(), http.StatusOK)

	// Reload with associations
	h.db.Preload("Scopes").Preload("Audiences").First(&app, app.ID)

	c.JSON(http.StatusOK, app)
}

func (h *AdminHandler) DeleteApplication(c *gin.Context) {
	id := c.Param("id")

	result := h.db.Where("id = ?", id).Delete(&database.Application{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete application"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Application not found"})
		return
	}

	// Log audit event
	h.logAudit(c, "application.delete", "application", id, http.StatusNoContent)

	c.JSON(http.StatusNoContent, nil)
}

// Scope Handlers

func (h *AdminHandler) ListScopes(c *gin.Context) {
	var scopes []database.Scope
	if err := h.db.Find(&scopes).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scopes"})
		return
	}
	c.JSON(http.StatusOK, scopes)
}

func (h *AdminHandler) CreateScope(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		IsDefault   bool   `json:"is_default"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scope := database.Scope{
		Name:        req.Name,
		Description: req.Description,
		IsDefault:   req.IsDefault,
	}

	if err := h.db.Create(&scope).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create scope"})
		return
	}

	// Log audit event
	h.logAudit(c, "scope.create", "scope", scope.ID.String(), http.StatusCreated)

	c.JSON(http.StatusCreated, scope)
}

func (h *AdminHandler) GetScope(c *gin.Context) {
	id := c.Param("id")

	var scope database.Scope
	if err := h.db.Where("id = ?", id).First(&scope).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Scope not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scope"})
		return
	}

	c.JSON(http.StatusOK, scope)
}

func (h *AdminHandler) UpdateScope(c *gin.Context) {
	id := c.Param("id")

	var scope database.Scope
	if err := h.db.Where("id = ?", id).First(&scope).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Scope not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch scope"})
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		IsDefault   *bool  `json:"is_default"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != "" {
		scope.Name = req.Name
	}
	scope.Description = req.Description
	if req.IsDefault != nil {
		scope.IsDefault = *req.IsDefault
	}

	if err := h.db.Save(&scope).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update scope"})
		return
	}

	// Log audit event
	h.logAudit(c, "scope.update", "scope", scope.ID.String(), http.StatusOK)

	c.JSON(http.StatusOK, scope)
}

func (h *AdminHandler) DeleteScope(c *gin.Context) {
	id := c.Param("id")

	result := h.db.Where("id = ?", id).Delete(&database.Scope{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete scope"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Scope not found"})
		return
	}

	// Log audit event
	h.logAudit(c, "scope.delete", "scope", id, http.StatusNoContent)

	c.JSON(http.StatusNoContent, nil)
}

// Audience Handlers

func (h *AdminHandler) ListAudiences(c *gin.Context) {
	var audiences []database.Audience
	if err := h.db.Preload("Scopes").Find(&audiences).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch audiences"})
		return
	}
	c.JSON(http.StatusOK, audiences)
}

func (h *AdminHandler) CreateAudience(c *gin.Context) {
	var req struct {
		Identifier  string   `json:"identifier" binding:"required"`
		Name        string   `json:"name" binding:"required"`
		Description string   `json:"description"`
		ScopeIDs    []string `json:"scope_ids"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	audience := database.Audience{
		Identifier:  req.Identifier,
		Name:        req.Name,
		Description: req.Description,
	}

	tx := h.db.Begin()

	if err := tx.Create(&audience).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create audience"})
		return
	}

	// Assign scopes
	if len(req.ScopeIDs) > 0 {
		var scopes []database.Scope
		if err := tx.Where("id IN ?", req.ScopeIDs).Find(&scopes).Error; err == nil && len(scopes) > 0 {
			if err := tx.Model(&audience).Association("Scopes").Replace(scopes); err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign scopes"})
				return
			}
		}
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// Log audit event
	h.logAudit(c, "audience.create", "audience", audience.ID.String(), http.StatusCreated)

	// Reload with associations
	h.db.Preload("Scopes").First(&audience, audience.ID)

	c.JSON(http.StatusCreated, audience)
}

func (h *AdminHandler) GetAudience(c *gin.Context) {
	id := c.Param("id")

	var audience database.Audience
	if err := h.db.Preload("Scopes").Where("id = ?", id).First(&audience).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Audience not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch audience"})
		return
	}

	c.JSON(http.StatusOK, audience)
}

func (h *AdminHandler) UpdateAudience(c *gin.Context) {
	id := c.Param("id")

	var audience database.Audience
	if err := h.db.Where("id = ?", id).First(&audience).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "Audience not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch audience"})
		return
	}

	var req struct {
		Identifier  string   `json:"identifier"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		ScopeIDs    []string `json:"scope_ids"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Identifier != "" {
		audience.Identifier = req.Identifier
	}
	if req.Name != "" {
		audience.Name = req.Name
	}
	audience.Description = req.Description

	tx := h.db.Begin()

	if err := tx.Save(&audience).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update audience"})
		return
	}

	// Update scopes
	if req.ScopeIDs != nil {
		var scopes []database.Scope
		if len(req.ScopeIDs) > 0 {
			tx.Where("id IN ?", req.ScopeIDs).Find(&scopes)
		}
		if err := tx.Model(&audience).Association("Scopes").Replace(scopes); err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update scopes"})
			return
		}
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// Log audit event
	h.logAudit(c, "audience.update", "audience", audience.ID.String(), http.StatusOK)

	// Reload with associations
	h.db.Preload("Scopes").First(&audience, audience.ID)

	c.JSON(http.StatusOK, audience)
}

func (h *AdminHandler) DeleteAudience(c *gin.Context) {
	id := c.Param("id")

	result := h.db.Where("id = ?", id).Delete(&database.Audience{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete audience"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Audience not found"})
		return
	}

	// Log audit event
	h.logAudit(c, "audience.delete", "audience", id, http.StatusNoContent)

	c.JSON(http.StatusNoContent, nil)
}

// User Handlers

func (h *AdminHandler) ListUsers(c *gin.Context) {
	var users []database.User
	query := h.db.Preload("Roles")

	// Optional filtering
	if search := c.Query("search"); search != "" {
		query = query.Where("username ILIKE ? OR email ILIKE ?", "%"+search+"%", "%"+search+"%")
	}

	if err := query.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}

	c.JSON(http.StatusOK, users)
}

func (h *AdminHandler) CreateUser(c *gin.Context) {
	var req struct {
		Username string   `json:"username" binding:"required"`
		Email    string   `json:"email" binding:"required,email"`
		Password string   `json:"password" binding:"required,min=8"`
		IsActive bool     `json:"is_active"`
		IsAdmin  bool     `json:"is_admin"`
		RoleIDs  []string `json:"role_ids"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user := database.User{
		Username: req.Username,
		Email:    req.Email,
		Password: string(hashedPassword),
		IsActive: req.IsActive,
		IsAdmin:  req.IsAdmin,
	}

	tx := h.db.Begin()

	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	// Assign roles
	if len(req.RoleIDs) > 0 {
		var roles []database.Role
		if err := tx.Where("id IN ?", req.RoleIDs).Find(&roles).Error; err == nil && len(roles) > 0 {
			if err := tx.Model(&user).Association("Roles").Replace(roles); err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assign roles"})
				return
			}
		}
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// Log audit event
	h.logAudit(c, "user.create", "user", user.ID.String(), http.StatusCreated)

	// Reload with associations
	h.db.Preload("Roles").First(&user, user.ID)

	c.JSON(http.StatusCreated, user)
}

func (h *AdminHandler) GetUser(c *gin.Context) {
	id := c.Param("id")

	var user database.User
	if err := h.db.Preload("Roles").Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		return
	}

	c.JSON(http.StatusOK, user)
}

func (h *AdminHandler) UpdateUser(c *gin.Context) {
	id := c.Param("id")

	var user database.User
	if err := h.db.Where("id = ?", id).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user"})
		return
	}

	var req struct {
		Username string   `json:"username"`
		Email    string   `json:"email" binding:"omitempty,email"`
		Password string   `json:"password" binding:"omitempty,min=8"`
		IsActive *bool    `json:"is_active"`
		IsAdmin  *bool    `json:"is_admin"`
		RoleIDs  []string `json:"role_ids"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Update fields
	if req.Username != "" {
		user.Username = req.Username
	}
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		user.Password = string(hashedPassword)
	}
	if req.IsActive != nil {
		user.IsActive = *req.IsActive
	}
	if req.IsAdmin != nil {
		user.IsAdmin = *req.IsAdmin
	}

	tx := h.db.Begin()

	if err := tx.Save(&user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	// Update roles
	if req.RoleIDs != nil {
		var roles []database.Role
		if len(req.RoleIDs) > 0 {
			tx.Where("id IN ?", req.RoleIDs).Find(&roles)
		}
		if err := tx.Model(&user).Association("Roles").Replace(roles); err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update roles"})
			return
		}
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
		return
	}

	// Log audit event
	h.logAudit(c, "user.update", "user", user.ID.String(), http.StatusOK)

	// Reload with associations
	h.db.Preload("Roles").First(&user, user.ID)

	c.JSON(http.StatusOK, user)
}

func (h *AdminHandler) DeleteUser(c *gin.Context) {
	id := c.Param("id")

	// Prevent deleting yourself
	currentUserID := c.GetString("user_id")
	if id == currentUserID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete your own account"})
		return
	}

	result := h.db.Where("id = ?", id).Delete(&database.User{})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Log audit event
	h.logAudit(c, "user.delete", "user", id, http.StatusNoContent)

	c.JSON(http.StatusNoContent, nil)
}

// Audit Log Handlers

func (h *AdminHandler) ListAuditLogs(c *gin.Context) {
	var logs []database.AuditLog
	// Note: Preload("Application") removed due to GORM parsing issues with database.StringArray
	// Application details can be fetched separately if needed
	query := h.db.Preload("User").Order("created_at DESC")

	// Optional filtering
	if userID := c.Query("user_id"); userID != "" {
		query = query.Where("user_id = ?", userID)
	}
	if appID := c.Query("application_id"); appID != "" {
		query = query.Where("application_id = ?", appID)
	}
	if action := c.Query("action"); action != "" {
		query = query.Where("action = ?", action)
	}

	// Pagination
	page := 1
	limit := 50
	if p := c.Query("page"); p != "" {
		if parsedPage, err := strconv.Atoi(p); err == nil {
			page = parsedPage
		}
	}
	if l := c.Query("limit"); l != "" {
		if parsedLimit, err := strconv.Atoi(l); err == nil {
			limit = parsedLimit
		}
	}
	offset := (page - 1) * limit

	var total int64
	query.Model(&database.AuditLog{}).Count(&total)

	if err := query.Limit(limit).Offset(offset).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch audit logs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":  logs,
		"total": total,
		"page":  page,
		"limit": limit,
	})
}

// Statistics Handler

func (h *AdminHandler) GetStatistics(c *gin.Context) {
	var stats struct {
		Applications int64 `json:"applications"`
		Users        int64 `json:"users"`
		Scopes       int64 `json:"scopes"`
		Audiences    int64 `json:"audiences"`
		ActiveTokens int64 `json:"active_tokens"`
	}

	h.db.Model(&database.Application{}).Count(&stats.Applications)
	h.db.Model(&database.User{}).Count(&stats.Users)
	h.db.Model(&database.Scope{}).Count(&stats.Scopes)
	h.db.Model(&database.Audience{}).Count(&stats.Audiences)
	h.db.Model(&database.Token{}).Where("expires_at > NOW() AND revoked = false").Count(&stats.ActiveTokens)

	c.JSON(http.StatusOK, stats)
}

// Helper function to log audit events
func (h *AdminHandler) logAudit(c *gin.Context, action, resource, resourceID string, statusCode int) {
	audit := database.AuditLog{
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.GetHeader("User-Agent"),
		StatusCode: statusCode,
		Metadata: map[string]interface{}{
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

	// Get application ID from context
	if appID := c.GetString("client_id"); appID != "" {
		var app database.Application
		if err := h.db.Where("client_id = ?", appID).First(&app).Error; err == nil {
			audit.ApplicationID = &app.ID
		}
	}

	h.db.Create(&audit)
}
