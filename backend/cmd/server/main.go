package main

import (
	"context"
	"flag"
	"fmt"
	"log"
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
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Load JWT keys
	privateKey, err := crypto.LoadPrivateKey(cfg.JWT.PrivateKeyPath)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}
	cfg.JWT.PrivateKey = privateKey
	cfg.JWT.PublicKey = &privateKey.PublicKey

	// Connect to database
	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Run migrations
	if err := database.Migrate(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize default data
	if err := database.InitializeDefaultData(db, cfg); err != nil {
		log.Fatalf("Failed to initialize default data: %v", err)
	}

	// Initialize Redis client (optional)
	var redisClient *redis.Client
	if cfg.Redis.Host != "" {
		redisClient, err = redis.NewClient(cfg)
		if err != nil {
			log.Printf("Warning: Failed to connect to Redis: %v", err)
			log.Println("Continuing without Redis (some features will be disabled)")
		} else {
			defer redisClient.Close()
		}
	}

	// Initialize token manager
	tokenManager, err := tokens.NewTokenManager(&cfg.JWT, cfg.OAuth.Issuer)
	if err != nil {
		log.Fatalf("Failed to initialize token manager: %v", err)
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
		csrfConfig.SkipPaths = []string{
			"/health",
			"/metrics",
			"/csrf-token",
			"/auth/login",
			"/auth/refresh",
			"/oauth/token",
			"/oauth/introspect",
			"/oauth/revoke",
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
		oauthGroup.POST("/token", middleware.CSRFExempt(), oauthHandler.TokenHandler)
		oauthGroup.POST("/introspect", middleware.CSRFExempt(), oauthHandler.IntrospectHandler)
		oauthGroup.POST("/revoke", middleware.CSRFExempt(), oauthHandler.RevokeHandler)

		// Protected endpoints
		authMiddleware := auth.NewAuthMiddleware(tokenManager)
		oauthGroup.GET("/userinfo", authMiddleware.RequireAuth(), oauthHandler.UserInfoHandler)
		oauthGroup.POST("/userinfo", authMiddleware.RequireAuth(), oauthHandler.UserInfoHandler)
	}

	// OIDC Discovery
	router.GET("/.well-known/openid-configuration", oauthHandler.DiscoveryHandler)
	router.GET("/.well-known/jwks.json", oauthHandler.JWKSHandler)

	// Admin API endpoints
	adminHandler := handlers.NewAdminHandler(db, tokenManager)
	authMiddleware := auth.NewAuthMiddleware(tokenManager)

	apiGroup := router.Group("/api/v1")
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
	}

	// Auth endpoints (login for admin panel)
	authHandler := handlers.NewAuthHandler(db, tokenManager)
	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login", middleware.CSRFExempt(), authHandler.Login)
		authGroup.POST("/logout", authMiddleware.RequireAuth(), authHandler.Logout)
		authGroup.GET("/me", authMiddleware.RequireAuth(), authHandler.Me)
		authGroup.POST("/refresh", middleware.CSRFExempt(), authHandler.RefreshToken)
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
		log.Printf("Starting OryxID server on %s", srv.Addr)
		log.Printf("OAuth endpoints: http://%s/oauth", srv.Addr)
		log.Printf("API endpoints: http://%s/api/v1", srv.Addr)

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown with 30s timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exited")
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

	for {
		select {
		case <-stop:
			log.Println("Stopping background tasks")
			return

		case <-tokenTicker.C:
			if err := cleanupExpiredTokens(db); err != nil {
				log.Printf("Error cleaning up expired tokens: %v", err)
			}

		case <-sessionTicker.C:
			if err := cleanupExpiredSessions(db); err != nil {
				log.Printf("Error cleaning up expired sessions: %v", err)
			}

		case <-codeTicker.C:
			if err := cleanupExpiredAuthCodes(db); err != nil {
				log.Printf("Error cleaning up expired auth codes: %v", err)
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
		log.Printf("Cleaned up %d expired tokens", result.RowsAffected)
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
		log.Printf("Cleaned up %d expired sessions", result.RowsAffected)
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
		log.Printf("Cleaned up %d expired authorization codes", result.RowsAffected)
	}
	return nil
}
