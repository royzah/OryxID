package database

import (
	"fmt"
	"log"
	"time"

	"github.com/tiiuae/oryxid/internal/config"
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

	// Create indexes
	if err := CreateIndexes(db); err != nil {
		log.Printf("Warning: Failed to create some indexes: %v", err)
	}

	log.Println("Database migration completed successfully")
	return nil
}

// CreateIndexes creates database indexes for performance
func CreateIndexes(db *gorm.DB) error {
	indexes := []string{
		// User indexes
		"CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
		"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",

		// Application indexes
		"CREATE INDEX IF NOT EXISTS idx_applications_client_id ON applications(client_id)",
		"CREATE INDEX IF NOT EXISTS idx_applications_owner_id ON applications(owner_id)",

		// Token indexes
		"CREATE INDEX IF NOT EXISTS idx_tokens_token_hash ON tokens(token_hash)",
		"CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_tokens_application_id ON tokens(application_id)",
		"CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id)",

		// Authorization code indexes
		"CREATE INDEX IF NOT EXISTS idx_authorization_codes_code ON authorization_codes(code)",
		"CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at)",

		// Session indexes
		"CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",

		// Audit log indexes
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_application_id ON audit_logs(application_id)",
		"CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)",
	}

	for _, idx := range indexes {
		if err := db.Exec(idx).Error; err != nil {
			log.Printf("Failed to create index: %s - %v", idx, err)
		}
	}

	return nil
}

// InitializeDefaultData creates minimal required data
func InitializeDefaultData(db *gorm.DB, cfg *config.Config) error {
	// Create basic roles
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
			log.Printf("Created role: %s", role.Name)
		}
	}

	// Create basic permissions
	permissions := []Permission{
		{Name: "applications:read", Description: "Read applications"},
		{Name: "applications:write", Description: "Create and update applications"},
		{Name: "applications:delete", Description: "Delete applications"},
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
			log.Printf("Created permission: %s", perm.Name)
		}
	}

	// Assign permissions to admin role
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

	// Create admin user only if configured
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
			log.Printf("Created admin user: %s", cfg.Admin.Username)
		}
	}

	// Create basic OpenID Connect scopes (minimal set)
	basicScopes := []Scope{
		{Name: "openid", Description: "OpenID Connect scope", IsDefault: false},
		{Name: "profile", Description: "Access to user profile", IsDefault: false},
		{Name: "email", Description: "Access to user email", IsDefault: false},
		{Name: "offline_access", Description: "Offline access for refresh tokens", IsDefault: false},
	}

	for _, scope := range basicScopes {
		var existing Scope
		if err := db.Where("name = ?", scope.Name).First(&existing).Error; err == gorm.ErrRecordNotFound {
			if err := db.Create(&scope).Error; err != nil {
				return fmt.Errorf("failed to create scope %s: %w", scope.Name, err)
			}
			log.Printf("Created scope: %s", scope.Name)
		}
	}

	return nil
}
