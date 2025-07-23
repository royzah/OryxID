package config

import (
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
	"github.com/tiiuae/oryxid/pkg/crypto"
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

	// Set defaults
	setDefaults()

	// Read environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("ORYXID")

	// Read config file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Unmarshal config
	cfg = &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %w", err)
	}

	// Set JWT signing method
	cfg.JWT.SigningMethod = jwt.SigningMethodRS256

	// Load JWT keys
	if err := loadJWTKeys(cfg); err != nil {
		return nil, fmt.Errorf("error loading JWT keys: %w", err)
	}

	return cfg, nil
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
	viper.SetDefault("oauth.issuer", "https://localhost:9000")
	viper.SetDefault("oauth.authorizationcodelifespan", "10m")
	viper.SetDefault("oauth.accesstokenlifespan", "1h")
	viper.SetDefault("oauth.refreshtokenlifespan", "720h")
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

func loadJWTKeys(cfg *Config) error {
	// Try to load private key
	privateKey, err := crypto.LoadPrivateKey(cfg.JWT.PrivateKeyPath)
	if err != nil {
		// If file doesn't exist, generate new keys
		privateKey, err = crypto.GenerateRSAKeyPair(4096)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key pair: %w", err)
		}

		// Save the generated keys
		if err := crypto.SavePrivateKey(privateKey, cfg.JWT.PrivateKeyPath); err != nil {
			return fmt.Errorf("failed to save private key: %w", err)
		}

		if err := crypto.SavePublicKey(&privateKey.PublicKey, cfg.JWT.PublicKeyPath); err != nil {
			return fmt.Errorf("failed to save public key: %w", err)
		}
	}

	cfg.JWT.PrivateKey = privateKey
	cfg.JWT.PublicKey = &privateKey.PublicKey

	return nil
}

func Get() *Config {
	if cfg == nil {
		panic("config not loaded")
	}
	return cfg
}

func GetDSN() string {
	db := Get().Database
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		db.Host, db.Port, db.User, db.Password, db.Name, db.SSLMode)
}
