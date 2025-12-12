package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tiiuae/oryxid/internal/auth"
	"github.com/tiiuae/oryxid/internal/config"
	"github.com/tiiuae/oryxid/internal/database"
	"github.com/tiiuae/oryxid/internal/handlers"
	"github.com/tiiuae/oryxid/internal/logger"
	"github.com/tiiuae/oryxid/internal/middleware"
	"github.com/tiiuae/oryxid/internal/oauth"
	"github.com/tiiuae/oryxid/internal/redis"
	"github.com/tiiuae/oryxid/internal/tokens"
	"github.com/tiiuae/oryxid/pkg/crypto"
	"gorm.io/gorm"
)

func main() {
	// Parse command line flags
	var healthCheck bool
	flag.BoolVar(&healthCheck, "health", false, "Run health check")
	flag.Parse()

	// If health check flag is set, just check if the service can start
	if healthCheck {
		fmt.Println("OK")
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("Failed to load configuration", "error", err)
	}

	// Initialize structured logger with config
	logger.Initialize(logger.Config{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
	})

	logger.Info("Configuration loaded",
		"server_mode", cfg.Server.Mode,
		"log_level", cfg.Log.Level,
	)

	// Load JWT keys
	privateKey, err := crypto.LoadPrivateKey(cfg.JWT.PrivateKeyPath)
	if err != nil {
		logger.Fatal("Failed to load private key", "error", err, "path", cfg.JWT.PrivateKeyPath)
	}
	cfg.JWT.PrivateKey = privateKey
	cfg.JWT.PublicKey = &privateKey.PublicKey

	// Connect to database
	db, err := database.Connect(cfg)
	if err != nil {
		logger.Fatal("Failed to connect to database", "error", err)
	}
	logger.Info("Database connected", "host", cfg.Database.Host, "name", cfg.Database.Name)

	// Run migrations
	if err := database.Migrate(db); err != nil {
		logger.Fatal("Failed to run migrations", "error", err)
	}
	logger.Debug("Database migrations completed")

	// Initialize default data
	if err := database.InitializeDefaultData(db, cfg); err != nil {
		logger.Fatal("Failed to initialize default data", "error", err)
	}

	// Create performance indexes
	if err := database.CreateIndexes(db); err != nil {
		logger.Warn("Failed to create some indexes", "error", err)
	}
	logger.Debug("Database indexes created")

	// Initialize Redis client (optional)
	var redisClient *redis.Client
	if cfg.Redis.Host != "" {
		redisClient, err = redis.NewClient(cfg)
		if err != nil {
			logger.Warn("Failed to connect to Redis, continuing without it",
				"error", err,
				"host", cfg.Redis.Host,
			)
		} else {
			defer redisClient.Close()
			logger.Info("Redis connected", "host", cfg.Redis.Host)
		}
	}

	// Initialize token manager
	tokenManager, err := tokens.NewTokenManager(&cfg.JWT, cfg.OAuth.Issuer)
	if err != nil {
		logger.Fatal("Failed to initialize token manager", "error", err)
	}

	// Initialize OAuth server
	oauthServer := oauth.NewServer(db, tokenManager)

	// Start background cleanup tasks
	stopCleanup := make(chan struct{})
	go startBackgroundTasks(db, stopCleanup)
	defer close(stopCleanup)

	// Set Gin mode
	gin.SetMode(cfg.Server.Mode)

	// Create router
	router := gin.Default()

	// Apply global middleware
	router.Use(middleware.CORS(cfg.OAuth.AllowedOrigins))
	router.Use(middleware.Security())
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger())
	router.Use(middleware.Recovery())

	// Rate limiting (with Redis if available)
	if cfg.Security.RateLimitEnabled {
		var limiter middleware.RateLimiter
		if redisClient != nil {
			limiter = middleware.NewRedisRateLimiter(redisClient, cfg.Security.RateLimitRPS)
		} else {
			limiter = middleware.NewInMemoryRateLimiter(cfg.Security.RateLimitRPS, cfg.Security.RateLimitBurst)
		}
		router.Use(middleware.RateLimit(limiter))
	}

	// CSRF protection for web endpoints
	if cfg.Security.CSRFEnabled {
		csrfConfig := middleware.DefaultCSRFConfig()
		csrfConfig.RedisClient = redisClient
		csrfConfig.CookieSecure = cfg.Server.Mode == "release" // Only secure in production
		csrfConfig.CookieHTTPOnly = false                      // Allow JavaScript to read the cookie
		csrfConfig.SkipPaths = []string{
			"/health",
			"/metrics",
			"/auth/login",   // Login must be exempt - it's the entry point
			"/auth/logout",  // Logout is protected by JWT auth, not CSRF
			"/auth/refresh", // Token refresh should be exempt
			"/oauth/*",      // OAuth endpoints are protected by client credentials
			"/api/v1/*",     // API endpoints (use * for prefix matching)
			"/.well-known/openid-configuration",
			"/.well-known/jwks.json",
		}
		router.Use(middleware.CSRF(csrfConfig))
	}

	// Health check
	router.GET("/health", handlers.HealthHandler(db))

	// Metrics endpoint
	router.GET("/metrics", handlers.MetricsHandler())

	// CSRF token endpoint
	router.GET("/csrf-token", middleware.CSRFToken())

	// OAuth endpoints
	oauthHandler := handlers.NewOAuthHandler(oauthServer)
	oauthGroup := router.Group("/oauth")
	{
		// Public endpoints
		oauthGroup.GET("/authorize", oauthHandler.AuthorizeHandler)
		oauthGroup.POST("/authorize", oauthHandler.AuthorizeHandler)
		oauthGroup.POST("/token", oauthHandler.TokenHandler)
		oauthGroup.POST("/introspect", oauthHandler.IntrospectHandler)
		oauthGroup.POST("/revoke", oauthHandler.RevokeHandler)
		oauthGroup.POST("/par", oauthHandler.PARHandler)                                  // RFC 9126 - Pushed Authorization Requests
		oauthGroup.POST("/device_authorization", oauthHandler.DeviceAuthorizationHandler) // RFC 8628 - Device Authorization Grant
		oauthGroup.GET("/device", oauthHandler.DeviceVerifyHandler)                       // RFC 8628 - User verification page
		oauthGroup.POST("/bc-authorize", oauthHandler.CIBAHandler)                        // OpenID Connect CIBA

		// Protected endpoints
		authMiddleware := auth.NewAuthMiddleware(tokenManager, db)
		oauthGroup.GET("/userinfo", authMiddleware.RequireAuth(), oauthHandler.UserInfoHandler)
		oauthGroup.POST("/userinfo", authMiddleware.RequireAuth(), oauthHandler.UserInfoHandler)
		oauthGroup.POST("/device", authMiddleware.RequireAuth(), oauthHandler.DeviceAuthorizeHandler) // RFC 8628 - User authorization
	}

	// OIDC Discovery
	router.GET("/.well-known/openid-configuration", oauthHandler.DiscoveryHandler)
	router.GET("/.well-known/jwks.json", oauthHandler.JWKSHandler)

	// Admin API endpoints
	adminHandler := handlers.NewAdminHandler(db, tokenManager)
	authMiddleware := auth.NewAuthMiddleware(tokenManager, db)

	apiGroup := router.Group("/api/v1")
	apiGroup.Use(middleware.CSRFExempt()) // API uses Bearer tokens, not cookies - exempt from CSRF
	apiGroup.Use(authMiddleware.RequireAuth())
	{
		// Applications
		apiGroup.GET("/applications", adminHandler.ListApplications)
		apiGroup.POST("/applications", adminHandler.CreateApplication)
		apiGroup.GET("/applications/:id", adminHandler.GetApplication)
		apiGroup.PUT("/applications/:id", adminHandler.UpdateApplication)
		apiGroup.DELETE("/applications/:id", adminHandler.DeleteApplication)

		// Scopes
		apiGroup.GET("/scopes", adminHandler.ListScopes)
		apiGroup.POST("/scopes", adminHandler.CreateScope)
		apiGroup.GET("/scopes/:id", adminHandler.GetScope)
		apiGroup.PUT("/scopes/:id", adminHandler.UpdateScope)
		apiGroup.DELETE("/scopes/:id", adminHandler.DeleteScope)

		// Audiences
		apiGroup.GET("/audiences", adminHandler.ListAudiences)
		apiGroup.POST("/audiences", adminHandler.CreateAudience)
		apiGroup.GET("/audiences/:id", adminHandler.GetAudience)
		apiGroup.PUT("/audiences/:id", adminHandler.UpdateAudience)
		apiGroup.DELETE("/audiences/:id", adminHandler.DeleteAudience)

		// Users (require admin role)
		userGroup := apiGroup.Group("/users")
		userGroup.Use(authMiddleware.RequireAdmin())
		{
			userGroup.GET("", adminHandler.ListUsers)
			userGroup.POST("", adminHandler.CreateUser)
			userGroup.GET("/:id", adminHandler.GetUser)
			userGroup.PUT("/:id", adminHandler.UpdateUser)
			userGroup.DELETE("/:id", adminHandler.DeleteUser)
		}

		// Audit logs (require admin role)
		apiGroup.GET("/audit-logs", authMiddleware.RequireAdmin(), adminHandler.ListAuditLogs)

		// Statistics
		apiGroup.GET("/stats", adminHandler.GetStatistics)

		// Settings (require admin role)
		settingsGroup := apiGroup.Group("/settings")
		settingsGroup.Use(authMiddleware.RequireAdmin())
		{
			settingsGroup.GET("", adminHandler.GetSettings)
			settingsGroup.PUT("", adminHandler.UpdateSettings)
			settingsGroup.POST("/revoke-all-tokens", adminHandler.RevokeAllTokens)
			settingsGroup.POST("/clear-sessions", adminHandler.ClearAllSessions)
		}
	}

	// Auth endpoints (login for admin panel)
	authHandler := handlers.NewAuthHandler(db, tokenManager)
	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login", authHandler.Login)
		authGroup.POST("/logout", authMiddleware.RequireAuth(), authHandler.Logout)
		authGroup.GET("/me", authMiddleware.RequireAuth(), authHandler.Me)
		authGroup.POST("/refresh", authHandler.RefreshToken)
		authGroup.POST("/change-password", authMiddleware.RequireAuth(), authHandler.ChangePassword)
	}

	// Session management endpoints (if Redis is available)
	if redisClient != nil {
		sessionHandler := handlers.NewSessionHandler(db, redisClient)
		sessionGroup := router.Group("/sessions")
		sessionGroup.Use(authMiddleware.RequireAuth())
		{
			sessionGroup.GET("", sessionHandler.ListSessions)
			sessionGroup.DELETE("/:id", sessionHandler.RevokeSession)
			sessionGroup.DELETE("", sessionHandler.RevokeAllSessions)
		}
	}

	// Create HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Start server in goroutine
	go func() {
		logger.Info("Starting OryxID server",
			"addr", srv.Addr,
			"oauth_endpoint", fmt.Sprintf("http://%s/oauth", srv.Addr),
			"api_endpoint", fmt.Sprintf("http://%s/api/v1", srv.Addr),
		)

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Failed to start server", "error", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("Shutting down server...")

	// Graceful shutdown with 30s timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown", "error", err)
	}

	logger.Info("Server exited gracefully")
}

// startBackgroundTasks starts periodic cleanup tasks
func startBackgroundTasks(db *gorm.DB, stop <-chan struct{}) {
	// Clean up expired tokens every hour
	tokenTicker := time.NewTicker(time.Hour)
	defer tokenTicker.Stop()

	// Clean up expired sessions every 30 minutes
	sessionTicker := time.NewTicker(30 * time.Minute)
	defer sessionTicker.Stop()

	// Clean up expired authorization codes every 15 minutes
	codeTicker := time.NewTicker(15 * time.Minute)
	defer codeTicker.Stop()

	// Clean up expired device codes every 15 minutes (RFC 8628)
	deviceCodeTicker := time.NewTicker(15 * time.Minute)
	defer deviceCodeTicker.Stop()

	// Clean up expired CIBA requests every 5 minutes (they expire quickly)
	cibaTicker := time.NewTicker(5 * time.Minute)
	defer cibaTicker.Stop()

	logger.Debug("Background cleanup tasks started")

	for {
		select {
		case <-stop:
			logger.Info("Stopping background tasks")
			return

		case <-tokenTicker.C:
			if err := cleanupExpiredTokens(db); err != nil {
				logger.Error("Error cleaning up expired tokens", "error", err)
			}

		case <-sessionTicker.C:
			if err := cleanupExpiredSessions(db); err != nil {
				logger.Error("Error cleaning up expired sessions", "error", err)
			}

		case <-codeTicker.C:
			if err := cleanupExpiredAuthCodes(db); err != nil {
				logger.Error("Error cleaning up expired auth codes", "error", err)
			}

		case <-deviceCodeTicker.C:
			if err := cleanupExpiredDeviceCodes(db); err != nil {
				logger.Error("Error cleaning up expired device codes", "error", err)
			}

		case <-cibaTicker.C:
			if err := cleanupExpiredCIBARequests(db); err != nil {
				logger.Error("Error cleaning up expired CIBA requests", "error", err)
			}
		}
	}
}

func cleanupExpiredTokens(db *gorm.DB) error {
	result := db.Where("expires_at < ? AND revoked = false", time.Now()).
		Delete(&database.Token{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		logger.Info("Cleaned up expired tokens", "count", result.RowsAffected)
	}
	return nil
}

func cleanupExpiredSessions(db *gorm.DB) error {
	result := db.Where("expires_at < ?", time.Now()).
		Delete(&database.Session{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		logger.Info("Cleaned up expired sessions", "count", result.RowsAffected)
	}
	return nil
}

func cleanupExpiredAuthCodes(db *gorm.DB) error {
	result := db.Where("expires_at < ?", time.Now()).
		Delete(&database.AuthorizationCode{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		logger.Info("Cleaned up expired authorization codes", "count", result.RowsAffected)
	}
	return nil
}

func cleanupExpiredDeviceCodes(db *gorm.DB) error {
	result := db.Where("expires_at < ?", time.Now()).
		Delete(&database.DeviceCode{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		logger.Info("Cleaned up expired device codes", "count", result.RowsAffected)
	}
	return nil
}

func cleanupExpiredCIBARequests(db *gorm.DB) error {
	result := db.Where("expires_at < ?", time.Now()).
		Delete(&database.CIBAAuthenticationRequest{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		logger.Info("Cleaned up expired CIBA requests", "count", result.RowsAffected)
	}
	return nil
}
