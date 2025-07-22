package main

import (
	"context"
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
	"github.com/tiiuae/oryxid/internal/tokens"
	"github.com/tiiuae/oryxid/pkg/crypto"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Load JWT keys
	privateKey, publicKey, err := crypto.LoadOrGenerateKeys(cfg.JWT.PrivateKeyPath, cfg.JWT.PublicKeyPath)
	if err != nil {
		log.Fatalf("Failed to load JWT keys: %v", err)
	}
	cfg.JWT.PrivateKey = privateKey
	cfg.JWT.PublicKey = publicKey

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

	// Initialize token manager
	tokenManager, err := tokens.NewTokenManager(&cfg.JWT, cfg.OAuth.Issuer)
	if err != nil {
		log.Fatalf("Failed to initialize token manager: %v", err)
	}

	// Initialize OAuth server
	oauthServer := oauth.NewServer(db, tokenManager)

	// Initialize Redis (optional)
	// redisClient := redis.NewClient(&redis.Options{
	//     Addr:     fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
	//     Password: cfg.Redis.Password,
	//     DB:       cfg.Redis.DB,
	// })

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

	// Rate limiting (optional with Redis)
	// if cfg.Security.RateLimitEnabled {
	//     router.Use(middleware.RateLimit(redisClient, cfg.Security.RateLimitRPS, cfg.Security.RateLimitBurst))
	// }

	// Health check
	router.GET("/health", handlers.HealthHandler(db))

	// OAuth endpoints
	oauthHandler := handlers.NewOAuthHandler(oauthServer)
	oauthGroup := router.Group("/oauth")
	{
		oauthGroup.GET("/authorize", oauthHandler.AuthorizeHandler)
		oauthGroup.POST("/authorize", oauthHandler.AuthorizeHandler)
		oauthGroup.POST("/token", oauthHandler.TokenHandler)
		oauthGroup.POST("/introspect", oauthHandler.IntrospectHandler)
		oauthGroup.POST("/revoke", oauthHandler.RevokeHandler)
		oauthGroup.GET("/userinfo", oauthHandler.UserInfoHandler)
		oauthGroup.POST("/userinfo", oauthHandler.UserInfoHandler)
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

		// Users
		apiGroup.GET("/users", adminHandler.ListUsers)
		apiGroup.POST("/users", adminHandler.CreateUser)
		apiGroup.GET("/users/:id", adminHandler.GetUser)
		apiGroup.PUT("/users/:id", adminHandler.UpdateUser)
		apiGroup.DELETE("/users/:id", adminHandler.DeleteUser)

		// Audit logs
		apiGroup.GET("/audit-logs", adminHandler.ListAuditLogs)

		// Statistics
		apiGroup.GET("/stats", adminHandler.GetStatistics)
	}

	// Auth endpoints (login for admin panel)
	authHandler := handlers.NewAuthHandler(db, tokenManager)
	router.POST("/auth/login", authHandler.Login)
	router.POST("/auth/logout", authMiddleware.RequireAuth(), authHandler.Logout)
	router.GET("/auth/me", authMiddleware.RequireAuth(), authHandler.Me)

	// Static files for admin UI (in production, serve from nginx/cdn)
	router.Static("/admin", "./frontend/dist")

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
