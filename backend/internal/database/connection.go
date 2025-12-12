package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tiiuae/oryxid/internal/config"
	applogger "github.com/tiiuae/oryxid/internal/logger"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// silentRecordNotFoundLogger wraps the default logger and suppresses ErrRecordNotFound
type silentRecordNotFoundLogger struct {
	logger.Interface
}

func (l *silentRecordNotFoundLogger) Trace(ctx context.Context, begin time.Time, fc func() (sql string, rowsAffected int64), err error) {
	// Suppress ErrRecordNotFound - it's expected behavior, not an error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return
	}
	l.Interface.Trace(ctx, begin, fc, err)
}

// Connect establishes a connection to the database
func Connect(cfg *config.Config) (*gorm.DB, error) {
	dsn := config.GetDSN()

	// Configure GORM logger - wrap default to suppress ErrRecordNotFound
	var gormLogger logger.Interface
	if cfg.Server.Mode == "release" {
		gormLogger = logger.Default.LogMode(logger.Silent)
	} else {
		gormLogger = &silentRecordNotFoundLogger{Interface: logger.Default}
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

	applogger.Info("Successfully connected to database")
	return db, nil
}

// Migrate runs database migrations
func Migrate(db *gorm.DB) error {
	// Enable UUID extension
	if err := db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"").Error; err != nil {
		return fmt.Errorf("failed to create uuid extension: %w", err)
	}

	applogger.Debug("Creating all tables manually...")

	// Create permissions table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS permissions (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			name TEXT UNIQUE NOT NULL,
			description TEXT
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create permissions table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_permissions_deleted_at ON permissions(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create permissions index: %w", err)
	}

	// Create roles table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS roles (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			name TEXT UNIQUE NOT NULL,
			description TEXT
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create roles table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_roles_deleted_at ON roles(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create roles index: %w", err)
	}

	// Create role_permissions junction table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS role_permissions (
			role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
			permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
			PRIMARY KEY (role_id, permission_id)
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create role_permissions table: %w", err)
	}

	// Create users table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			email_verified BOOLEAN DEFAULT FALSE,
			password TEXT NOT NULL,
			is_active BOOLEAN DEFAULT TRUE,
			is_admin BOOLEAN DEFAULT FALSE,
			totp_secret TEXT DEFAULT '',
			totp_enabled BOOLEAN DEFAULT FALSE,
			backup_codes JSONB DEFAULT '[]'
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}
	// Add MFA columns if they don't exist (for existing databases)
	db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT DEFAULT ''`)
	db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE`)
	db.Exec(`ALTER TABLE users ADD COLUMN IF NOT EXISTS backup_codes JSONB DEFAULT '[]'`)
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create users index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`).Error; err != nil {
		return fmt.Errorf("failed to create users username index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`).Error; err != nil {
		return fmt.Errorf("failed to create users email index: %w", err)
	}

	// Create user_roles junction table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS user_roles (
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
			PRIMARY KEY (user_id, role_id)
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create user_roles table: %w", err)
	}

	// Create signing_keys table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS signing_keys (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			key_id TEXT UNIQUE NOT NULL,
			algorithm TEXT NOT NULL,
			private_key_pem TEXT NOT NULL,
			public_key_pem TEXT NOT NULL,
			is_active BOOLEAN DEFAULT TRUE,
			activated_at TIMESTAMP WITH TIME ZONE NOT NULL,
			expires_at TIMESTAMP WITH TIME ZONE,
			revoked_at TIMESTAMP WITH TIME ZONE
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create signing_keys table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_signing_keys_deleted_at ON signing_keys(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create signing_keys deleted_at index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_signing_keys_is_active ON signing_keys(is_active)`).Error; err != nil {
		return fmt.Errorf("failed to create signing_keys is_active index: %w", err)
	}

	// Create sessions table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			session_id TEXT UNIQUE NOT NULL,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			data JSONB
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create sessions table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_deleted_at ON sessions(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create sessions index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id)`).Error; err != nil {
		return fmt.Errorf("failed to create sessions session_id index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`).Error; err != nil {
		return fmt.Errorf("failed to create sessions user_id index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`).Error; err != nil {
		return fmt.Errorf("failed to create sessions expires_at index: %w", err)
	}

	// Create applications table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS applications (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			name TEXT NOT NULL,
			description TEXT,
			client_id TEXT UNIQUE NOT NULL,
			hashed_client_secret TEXT NOT NULL,
			client_type TEXT NOT NULL,
			token_endpoint_auth_method TEXT,
			public_key_pem TEXT,
			jwks_uri TEXT,
			grant_types JSONB DEFAULT '[]'::jsonb,
			response_types JSONB DEFAULT '[]'::jsonb,
			redirect_uris JSONB DEFAULT '[]'::jsonb,
			post_logout_uris JSONB DEFAULT '[]'::jsonb,
			skip_authorization BOOLEAN DEFAULT FALSE,
			access_token_lifespan INTEGER,
			refresh_token_lifespan INTEGER,
			owner_id UUID REFERENCES users(id),
			metadata JSONB
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create applications table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_applications_deleted_at ON applications(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create applications index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_applications_client_id ON applications(client_id)`).Error; err != nil {
		return fmt.Errorf("failed to create applications client_id index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_applications_owner_id ON applications(owner_id)`).Error; err != nil {
		return fmt.Errorf("failed to create applications owner_id index: %w", err)
	}

	// Create scopes table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS scopes (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			name TEXT UNIQUE NOT NULL,
			description TEXT,
			is_default BOOLEAN DEFAULT FALSE
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create scopes table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_scopes_deleted_at ON scopes(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create scopes index: %w", err)
	}

	// Create audiences table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audiences (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			identifier TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			description TEXT
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create audiences table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_audiences_deleted_at ON audiences(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create audiences index: %w", err)
	}

	// Create application_scopes junction table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS application_scopes (
			application_id UUID REFERENCES applications(id) ON DELETE CASCADE,
			scope_id UUID REFERENCES scopes(id) ON DELETE CASCADE,
			PRIMARY KEY (application_id, scope_id)
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create application_scopes table: %w", err)
	}

	// Create application_audiences junction table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS application_audiences (
			application_id UUID REFERENCES applications(id) ON DELETE CASCADE,
			audience_id UUID REFERENCES audiences(id) ON DELETE CASCADE,
			PRIMARY KEY (application_id, audience_id)
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create application_audiences table: %w", err)
	}

	// Create audience_scopes junction table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audience_scopes (
			audience_id UUID REFERENCES audiences(id) ON DELETE CASCADE,
			scope_id UUID REFERENCES scopes(id) ON DELETE CASCADE,
			PRIMARY KEY (audience_id, scope_id)
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create audience_scopes table: %w", err)
	}

	// Create authorization_codes table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS authorization_codes (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			code TEXT UNIQUE NOT NULL,
			application_id UUID REFERENCES applications(id) ON DELETE CASCADE,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			redirect_uri TEXT NOT NULL,
			scope TEXT,
			audience TEXT,
			authorization_details TEXT,
			state TEXT,
			code_challenge TEXT,
			code_challenge_method TEXT,
			nonce TEXT,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			used BOOLEAN DEFAULT FALSE
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create authorization_codes table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_authorization_codes_deleted_at ON authorization_codes(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create authorization_codes index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_authorization_codes_code ON authorization_codes(code)`).Error; err != nil {
		return fmt.Errorf("failed to create authorization_codes code index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at)`).Error; err != nil {
		return fmt.Errorf("failed to create authorization_codes expires_at index: %w", err)
	}

	// Create tokens table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS tokens (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			token_hash TEXT UNIQUE NOT NULL,
			token_type TEXT NOT NULL,
			application_id UUID REFERENCES applications(id) ON DELETE CASCADE,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			scope TEXT,
			audience TEXT,
			authorization_details TEXT,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			revoked BOOLEAN DEFAULT FALSE,
			revoked_at TIMESTAMP WITH TIME ZONE
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create tokens table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_tokens_deleted_at ON tokens(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create tokens index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_tokens_token_hash ON tokens(token_hash)`).Error; err != nil {
		return fmt.Errorf("failed to create tokens token_hash index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at)`).Error; err != nil {
		return fmt.Errorf("failed to create tokens expires_at index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_tokens_application_id ON tokens(application_id)`).Error; err != nil {
		return fmt.Errorf("failed to create tokens application_id index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id)`).Error; err != nil {
		return fmt.Errorf("failed to create tokens user_id index: %w", err)
	}

	// Create audit_logs table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_logs (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			user_id UUID REFERENCES users(id) ON DELETE SET NULL,
			application_id UUID REFERENCES applications(id) ON DELETE SET NULL,
			action TEXT NOT NULL,
			resource TEXT,
			resource_id TEXT,
			ip_address TEXT,
			user_agent TEXT,
			status_code INTEGER,
			metadata JSONB
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create audit_logs table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_logs_deleted_at ON audit_logs(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create audit_logs index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)`).Error; err != nil {
		return fmt.Errorf("failed to create audit_logs created_at index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)`).Error; err != nil {
		return fmt.Errorf("failed to create audit_logs user_id index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_logs_application_id ON audit_logs(application_id)`).Error; err != nil {
		return fmt.Errorf("failed to create audit_logs application_id index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)`).Error; err != nil {
		return fmt.Errorf("failed to create audit_logs action index: %w", err)
	}

	// Create pushed_authorization_requests table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS pushed_authorization_requests (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			request_uri TEXT UNIQUE NOT NULL,
			application_id UUID NOT NULL,
			response_type TEXT NOT NULL,
			client_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			scope TEXT,
			state TEXT,
			nonce TEXT,
			code_challenge TEXT,
			code_challenge_method TEXT,
			authorization_details TEXT,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			used BOOLEAN DEFAULT FALSE
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create pushed_authorization_requests table: %w", err)
	}
	// Add authorization_details column if it doesn't exist (migration for existing tables)
	db.Exec(`ALTER TABLE pushed_authorization_requests ADD COLUMN IF NOT EXISTS authorization_details TEXT`)
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_pushed_authorization_requests_deleted_at ON pushed_authorization_requests(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create pushed_authorization_requests index: %w", err)
	}

	// Create ciba_authentication_requests table (OpenID Connect CIBA)
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS ciba_authentication_requests (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			auth_req_id TEXT UNIQUE NOT NULL,
			application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			binding_message TEXT,
			client_notify_token TEXT,
			scope TEXT,
			acr_values TEXT,
			login_hint TEXT,
			login_hint_token TEXT,
			id_token_hint TEXT,
			requested_expiry INTEGER,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			interval INTEGER DEFAULT 5,
			status TEXT DEFAULT 'pending',
			authorized_at TIMESTAMP WITH TIME ZONE,
			last_poll_at TIMESTAMP WITH TIME ZONE
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create ciba_authentication_requests table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_ciba_auth_req_id ON ciba_authentication_requests(auth_req_id)`).Error; err != nil {
		return fmt.Errorf("failed to create ciba auth_req_id index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_ciba_expires_at ON ciba_authentication_requests(expires_at)`).Error; err != nil {
		return fmt.Errorf("failed to create ciba expires_at index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_ciba_status ON ciba_authentication_requests(status)`).Error; err != nil {
		return fmt.Errorf("failed to create ciba status index: %w", err)
	}

	// Create device_codes table (RFC 8628 - Device Authorization Grant)
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS device_codes (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			device_code TEXT UNIQUE NOT NULL,
			user_code TEXT UNIQUE NOT NULL,
			application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
			user_id UUID REFERENCES users(id) ON DELETE CASCADE,
			scope TEXT,
			audience TEXT,
			verification_uri TEXT,
			expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
			interval INTEGER DEFAULT 5,
			status TEXT DEFAULT 'pending',
			authorized_at TIMESTAMP WITH TIME ZONE,
			last_poll_at TIMESTAMP WITH TIME ZONE,
			client_ip TEXT
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create device_codes table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_device_codes_deleted_at ON device_codes(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create device_codes index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_device_codes_device_code ON device_codes(device_code)`).Error; err != nil {
		return fmt.Errorf("failed to create device_codes device_code index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code)`).Error; err != nil {
		return fmt.Errorf("failed to create device_codes user_code index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at)`).Error; err != nil {
		return fmt.Errorf("failed to create device_codes expires_at index: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_device_codes_status ON device_codes(status)`).Error; err != nil {
		return fmt.Errorf("failed to create device_codes status index: %w", err)
	}

	// Create server_settings table
	if err := db.Exec(`
		CREATE TABLE IF NOT EXISTS server_settings (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			created_at TIMESTAMP WITH TIME ZONE,
			updated_at TIMESTAMP WITH TIME ZONE,
			deleted_at TIMESTAMP WITH TIME ZONE,
			key TEXT UNIQUE NOT NULL,
			value JSONB
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create server_settings table: %w", err)
	}
	if err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_server_settings_deleted_at ON server_settings(deleted_at)`).Error; err != nil {
		return fmt.Errorf("failed to create server_settings index: %w", err)
	}

	applogger.Debug("All tables created successfully")
	return nil
}

// CreateIndexes creates database indexes for performance
func CreateIndexes(db *gorm.DB) error {
	indexes := []string{
		// User indexes
		"CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
		"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
		"CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active)",

		// Application indexes
		"CREATE INDEX IF NOT EXISTS idx_applications_client_id ON applications(client_id)",
		"CREATE INDEX IF NOT EXISTS idx_applications_owner_id ON applications(owner_id)",
		"CREATE INDEX IF NOT EXISTS idx_applications_name ON applications(name)",

		// Token indexes
		"CREATE INDEX IF NOT EXISTS idx_tokens_token_hash ON tokens(token_hash)",
		"CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at)",
		"CREATE INDEX IF NOT EXISTS idx_tokens_application_id ON tokens(application_id)",
		"CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_tokens_revoked ON tokens(revoked)",
		"CREATE INDEX IF NOT EXISTS idx_tokens_expires_revoked ON tokens(expires_at, revoked)",

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

		// Scope and Audience indexes
		"CREATE INDEX IF NOT EXISTS idx_scopes_name ON scopes(name)",
		"CREATE INDEX IF NOT EXISTS idx_audiences_name ON audiences(name)",

		// PAR indexes
		"CREATE INDEX IF NOT EXISTS idx_par_request_uri ON pushed_authorization_requests(request_uri)",
		"CREATE INDEX IF NOT EXISTS idx_par_expires_at ON pushed_authorization_requests(expires_at)",
	}

	for _, idx := range indexes {
		if err := db.Exec(idx).Error; err != nil {
			applogger.Warn("Failed to create index", "index", idx, "error", err)
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
			applogger.Debug("Created role", "role", role.Name)
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
			applogger.Debug("Created permission", "permission", perm.Name)
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
			applogger.Warn("Failed to assign permissions to admin role", "error", err)
		}
		applogger.Debug("Assigned all permissions to admin role")
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
			applogger.Info("Created admin user", "username", cfg.Admin.Username)
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
			applogger.Debug("Created scope", "scope", scope.Name)
		}
	}

	// Initialize default server settings
	var existingSettings ServerSettings
	if err := db.Where("key = ?", "default").First(&existingSettings).Error; err == gorm.ErrRecordNotFound {
		defaultSettings := ServerSettings{
			Key: "default",
			Value: JSONB{
				"issuer":                    cfg.OAuth.Issuer,
				"access_token_lifespan":     3600,
				"refresh_token_lifespan":    86400,
				"id_token_lifespan":         3600,
				"auth_code_lifespan":        600,
				"require_pkce":              true,
				"rotate_refresh_tokens":     true,
				"revoke_old_refresh_tokens": true,
			},
		}
		if err := db.Create(&defaultSettings).Error; err != nil {
			return fmt.Errorf("failed to create default server settings: %w", err)
		}
		applogger.Debug("Created default server settings")
	}

	return nil
}
