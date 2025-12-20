// Example: Securing an API with OryxID SDK
package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	oryxid "github.com/tiiuae/oryxid/pkg/sdk"
)

func main() {
	// Initialize OryxID client
	client, err := oryxid.New(oryxid.Config{
		IssuerURL: "https://auth.example.com",
		// Optional: for introspection
		// ClientID:     "my-api-client",
		// ClientSecret: "secret",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Create Gin router
	r := gin.Default()

	// Create middleware
	auth := oryxid.NewGinMiddleware(client)

	// Public endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Protected endpoints
	api := r.Group("/api/v1")
	api.Use(auth.Protect())
	{
		// Any valid token can access
		api.GET("/profile", getProfile)

		// Requires specific scope
		api.GET("/billing", auth.RequireScope("billing:read"), getBilling)
		api.POST("/billing", auth.RequireScope("billing:write"), createBilling)

		// Requires any of the scopes
		api.GET("/reports", auth.RequireScopeAny("reports:read", "admin"), getReports)
	}

	log.Println("Server starting on :8080")
	r.Run(":8080")
}

func getProfile(c *gin.Context) {
	claims := oryxid.GetGinClaims(c)
	c.JSON(200, gin.H{
		"client_id": claims.ClientID,
		"subject":   claims.Subject,
		"scopes":    claims.GetScopes(),
	})
}

func getBilling(c *gin.Context) {
	c.JSON(200, gin.H{"invoices": []string{"INV-001", "INV-002"}})
}

func createBilling(c *gin.Context) {
	c.JSON(201, gin.H{"message": "billing created"})
}

func getReports(c *gin.Context) {
	c.JSON(200, gin.H{"reports": []string{"Q1-2024", "Q2-2024"}})
}

// Example with standard http package
func exampleStdLib() {
	client, _ := oryxid.New(oryxid.Config{
		IssuerURL: "https://auth.example.com",
	})

	mw := oryxid.NewMiddleware(client)

	mux := http.NewServeMux()

	// Protected endpoint
	mux.Handle("/api/data", mw.RequireScope("data:read")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := oryxid.GetClaims(r)
			w.Write([]byte("Hello, " + claims.ClientID))
		}),
	))

	http.ListenAndServe(":8080", mux)
}
