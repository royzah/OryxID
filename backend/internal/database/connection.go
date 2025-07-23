package database

import (
	"fmt"
	"log"
	"time"

	"github.com/tiiuae/oryxid/internal/config"
	"github.com/tiiuae/oryxid/pkg/crypto"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Connect establishes a connection to the database
func Connect(cfg *config.Config) (*gorm.DB, error) {
	dsn := config.GetDSN()

	// Configure GORM logger
	gormLogger := logger.Default
	if cfg.Server.Mode == "release" {
		gormLogger = logger.Default.LogMode(logger.Silent)
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormLogger,
		NowFunc: func() time.Time {
			return time.Now().UTC()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get underlying SQL database
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	// Configure connection pool
	sqlDB.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.Database.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.Database.ConnMaxLifetime)

	// Test connection
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Println("Successfully connected to database")
	return db, nil
}

// Migrate runs database migrations
func Migrate(db *gorm.DB) error {
	// Enable UUID extension
	if err := db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error; err != nil {
		return fmt.Errorf("failed to create uuid extension: %w", err)
	}

	// Auto migrate all models
	models := []interface{}{
		&User{},
		&Role{},
		&Permission{},
		&Application{},
		&Scope{},
		&Audience{},
		&AuthorizationCode{},
		&Token{},
		&Session{},
		&AuditLog{},
	}

	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			return fmt.Errorf("failed to migrate %T: %w", model, err)
		}
	}

	log.Println("Database migration completed successfully")
	return nil
}

// InitializeDefaultData creates default data if not exists
func InitializeDefaultData(db *gorm.DB, cfg *config.Config) error {
	// Create default roles
	roles := []Role{
		{Name: "admin", Description: "Administrator with full access"},
		{Name: "user", Description: "Regular user"},
	}

	for _, role := range roles {
		var existing Role
		if err := db.Where("name = ?", role.Name).First(&existing).Error; err == gorm.ErrRecordNotFound {
			if err := db.Create(&role).Error; err != nil {
				return fmt.Errorf("failed to create role %s: %w", role.Name, err)
			}
			log.Printf("Created default role: %s", role.Name)
		}
	}

	// Create default permissions
	permissions := []Permission{
		{Name: "applications:read", Description: "Read applications"},
		{Name: "applications:write", Description: "Create and update applications"},
		{Name: "applications:delete", Description: "Delete applications"},
		{Name: "scopes:read", Description: "Read scopes"},
		{Name: "scopes:write", Description: "Create and update scopes"},
		{Name: "scopes:delete", Description: "Delete scopes"},
		{Name: "users:read", Description: "Read users"},
		{Name: "users:write", Description: "Create and update users"},
		{Name: "users:delete", Description: "Delete users"},
		{Name: "audit:read", Description: "Read audit logs"},
	}

	for _, perm := range permissions {
		var existing Permission
		if err := db.Where("name = ?", perm.Name).First(&existing).Error; err == gorm.ErrRecordNotFound {
			if err := db.Create(&perm).Error; err != nil {
				return fmt.Errorf("failed to create permission %s: %w", perm.Name, err)
			}
			log.Printf("Created default permission: %s", perm.Name)
		}
	}

	// Assign all permissions to admin role
	var adminRole Role
	if err := db.Where("name = ?", "admin").First(&adminRole).Error; err == nil {
		var allPerms []Permission
		if err := db.Find(&allPerms).Error; err != nil {
			return fmt.Errorf("failed to find permissions: %w", err)
		}
		if err := db.Model(&adminRole).Association("Permissions").Replace(allPerms); err != nil {
			log.Printf("Failed to assign permissions to admin role: %v", err)
		}
		log.Println("Assigned all permissions to admin role")
	}

	// Create default admin user if configured
	if cfg.Admin.Username != "" && cfg.Admin.Email != "" && cfg.Admin.Password != "" {
		var existingUser User
		if err := db.Where("username = ? OR email = ?", cfg.Admin.Username, cfg.Admin.Email).First(&existingUser).Error; err == gorm.ErrRecordNotFound {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cfg.Admin.Password), cfg.Security.BCryptCost)
			if err != nil {
				return fmt.Errorf("failed to hash admin password: %w", err)
			}

			adminUser := User{
				Username: cfg.Admin.Username,
				Email:    cfg.Admin.Email,
				Password: string(hashedPassword),
				IsActive: true,
				IsAdmin:  true,
			}

			if err := db.Create(&adminUser).Error; err != nil {
				return fmt.Errorf("failed to create admin user: %w", err)
			}

			// Assign admin role
			if err := db.Model(&adminUser).Association("Roles").Append(&adminRole); err != nil {
				return fmt.Errorf("failed to assign admin role to user: %w", err)
			}
			log.Printf("Created default admin user: %s", cfg.Admin.Username)
		}
	}

	// Create default scopes
	defaultScopes := []Scope{
		{Name: "openid", Description: "OpenID Connect scope", IsDefault: true},
		{Name: "profile", Description: "Access to user profile", IsDefault: true},
		{Name: "email", Description: "Access to user email", IsDefault: true},
		{Name: "offline_access", Description: "Offline access for refresh tokens", IsDefault: false},
	}

	for _, scope := range defaultScopes {
		var existing Scope
		if err := db.Where("name = ?", scope.Name).First(&existing).Error; err == gorm.ErrRecordNotFound {
			if err := db.Create(&scope).Error; err != nil {
				return fmt.Errorf("failed to create scope %s: %w", scope.Name, err)
			}
			log.Printf("Created default scope: %s", scope.Name)
		}
	}

	// Create default test application (development only)
	if cfg.Server.Mode != "release" {
		var testApp Application
		if err := db.Where("name = ?", "Test Application").First(&testApp).Error; err == gorm.ErrRecordNotFound {
			clientID, _ := crypto.GenerateSecureToken(32)
			clientSecret, _ := crypto.GenerateSecureToken(64)

			testApp = Application{
				Name:              "Test Application",
				Description:       "Default test application for development",
				ClientID:          clientID,
				ClientSecret:      clientSecret,
				ClientType:        "confidential",
				GrantTypes:        []string{"authorization_code", "client_credentials", "refresh_token"},
				ResponseTypes:     []string{"code", "token"},
				RedirectURIs:      []string{"http://localhost:3000/callback", "http://localhost:8080/callback"},
				SkipAuthorization: true,
			}

			if err := db.Create(&testApp).Error; err != nil {
				return fmt.Errorf("failed to create test application: %w", err)
			}

			// Assign default scopes
			var scopes []Scope
			if err := db.Find(&scopes).Error; err != nil {
				return fmt.Errorf("failed to find scopes: %w", err)
			}
			if err := db.Model(&testApp).Association("Scopes").Replace(scopes); err != nil {
				log.Printf("Failed to assign scopes to test application: %v", err)
			}

			log.Printf("Created test application - Client ID: %s, Client Secret: %s", clientID, clientSecret)
		}
	}

	return nil
}
