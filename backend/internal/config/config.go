package config

import (
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	OAuth    OAuthConfig
	JWT      JWTConfig
	Security SecurityConfig
	Admin    AdminConfig
}

type ServerConfig struct {
	Host         string
	Port         int
	Mode         string // debug, release, test
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

type DatabaseConfig struct {
	Host            string
	Port            int
	User            string
	Password        string
	Name            string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

type RedisConfig struct {
	Host         string
	Port         int
	Password     string
	DB           int
	PoolSize     int
	MinIdleConns int
}

type OAuthConfig struct {
	Issuer                    string
	AuthorizationCodeLifespan time.Duration
	AccessTokenLifespan       time.Duration
	RefreshTokenLifespan      time.Duration
	IDTokenLifespan           time.Duration
	AllowedOrigins            []string
}

type JWTConfig struct {
	PrivateKey     *rsa.PrivateKey
	PublicKey      *rsa.PublicKey
	Kid            string
	SigningMethod  jwt.SigningMethod
	PrivateKeyPath string
	PublicKeyPath  string
}

type SecurityConfig struct {
	BCryptCost       int
	RateLimitEnabled bool
	RateLimitBurst   int
	RateLimitRPS     int
	PKCERequired     bool
	CSRFEnabled      bool
}

type AdminConfig struct {
	Username string
	Email    string
	Password string
}

var cfg *Config

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config")
	viper.AddConfigPath("/etc/oryxid/")

	setDefaults()

	// Environment setup
	viper.SetEnvPrefix("ORYXID")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	// Bind all environment variables
	bindEnvVars()

	// Try to read config file (optional)
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		// Config file not found is OK, we'll use env vars and defaults
	}

	// Unmarshal into our struct
	cfg = &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}

	// Set JWT specifics
	cfg.JWT.SigningMethod = jwt.SigningMethodRS256
	cfg.JWT.PrivateKeyPath = viper.GetString("jwt.privatekeypath")
	cfg.JWT.PublicKeyPath = viper.GetString("jwt.publickeypath")
	cfg.JWT.Kid = viper.GetString("jwt.kid")

	// Note: JWT keys will be loaded separately in main.go to avoid duplication

	return cfg, nil
}

func bindEnvVars() {
	envKeys := []string{
		// Server
		"server.host",
		"server.port",
		"server.mode",
		"server.readtimeout",
		"server.writetimeout",

		// Database
		"database.host",
		"database.port",
		"database.user",
		"database.password",
		"database.name",
		"database.sslmode",
		"database.maxopenconns",
		"database.maxidleconns",
		"database.connmaxlifetime",

		// Redis
		"redis.host",
		"redis.port",
		"redis.password",
		"redis.db",
		"redis.poolsize",
		"redis.minidleconns",

		// OAuth
		"oauth.issuer",
		"oauth.authorizationcodelifespan",
		"oauth.accesstokenlifespan",
		"oauth.refreshtokenlifespan",
		"oauth.idtokenlifespan",
		"oauth.allowedorigins",

		// JWT
		"jwt.privatekeypath",
		"jwt.publickeypath",
		"jwt.kid",

		// Security
		"security.bcryptcost",
		"security.ratelimitenabled",
		"security.ratelimitburst",
		"security.ratelimitrps",
		"security.pkcerequired",
		"security.csrfenabled",

		// Admin
		"admin.username",
		"admin.email",
		"admin.password",
	}

	for _, key := range envKeys {
		if err := viper.BindEnv(key); err != nil {
			// Log but don't fail - some keys might not be needed
			fmt.Printf("Warning: failed to bind env var %s: %v\n", key, err)
		}
	}
}

func setDefaults() {
	// Server defaults
	viper.SetDefault("server.host", "0.0.0.0")
	viper.SetDefault("server.port", 9000)
	viper.SetDefault("server.mode", "release")
	viper.SetDefault("server.readtimeout", "10s")
	viper.SetDefault("server.writetimeout", "10s")

	// Database defaults
	viper.SetDefault("database.host", "localhost")
	viper.SetDefault("database.port", 5432)
	viper.SetDefault("database.user", "oryxid")
	viper.SetDefault("database.name", "oryxid")
	viper.SetDefault("database.sslmode", "disable")
	viper.SetDefault("database.maxopenconns", 25)
	viper.SetDefault("database.maxidleconns", 5)
	viper.SetDefault("database.connmaxlifetime", "5m")

	// Redis defaults
	viper.SetDefault("redis.host", "localhost")
	viper.SetDefault("redis.port", 6379)
	viper.SetDefault("redis.db", 0)
	viper.SetDefault("redis.poolsize", 10)
	viper.SetDefault("redis.minidleconns", 5)

	// OAuth defaults
	viper.SetDefault("oauth.issuer", "http://localhost:9000")
	viper.SetDefault("oauth.authorizationcodelifespan", "10m")
	viper.SetDefault("oauth.accesstokenlifespan", "1h")
	viper.SetDefault("oauth.refreshtokenlifespan", "720h") // 30 days
	viper.SetDefault("oauth.idtokenlifespan", "1h")
	viper.SetDefault("oauth.allowedorigins", []string{"http://localhost:3000"})

	// Security defaults
	viper.SetDefault("security.bcryptcost", 12)
	viper.SetDefault("security.ratelimitenabled", true)
	viper.SetDefault("security.ratelimitburst", 10)
	viper.SetDefault("security.ratelimitrps", 100)
	viper.SetDefault("security.pkcerequired", true)
	viper.SetDefault("security.csrfenabled", true)

	// JWT defaults
	viper.SetDefault("jwt.privatekeypath", "./certs/private_key.pem")
	viper.SetDefault("jwt.publickeypath", "./certs/public_key.pem")
	viper.SetDefault("jwt.kid", "default-key-id")
}

// Get returns the loaded config (or panics if Load() wasn't called).
func Get() *Config {
	if cfg == nil {
		panic("config not loaded; call config.Load first")
	}
	return cfg
}

// GetDSN builds a PostgreSQL DSN string from the loaded config.
func GetDSN() string {
	c := Get()
	db := c.Database
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		db.Host, db.Port, db.User, db.Password, db.Name, db.SSLMode,
	)
}
