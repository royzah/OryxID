# OryxID SDK

Go SDK for validating tokens issued by OryxID.

## Installation

```bash
go get github.com/tiiuae/oryxid/pkg/sdk
```

## Quick Start

```go
package main

import (
    "log"
    "github.com/gin-gonic/gin"
    oryxid "github.com/tiiuae/oryxid/pkg/sdk"
)

func main() {
    client, err := oryxid.New(oryxid.Config{
        IssuerURL: "https://auth.example.com",
    })
    if err != nil {
        log.Fatal(err)
    }

    auth := oryxid.NewGinMiddleware(client)

    r := gin.Default()
    r.GET("/api/data", auth.RequireScope("data:read"), handler)
    r.Run(":8080")
}
```

## Token Validation

```go
// Local JWT validation (fast, uses cached JWKS)
claims, err := client.ValidateJWT(token)

// Introspection (real-time, requires client credentials)
result, err := client.Introspect(token)
```

## Scope Checking

Supports wildcard scopes:

```go
sc := oryxid.NewScopeChecker("billing:* inventory:read")

sc.Has("billing:read")    // true (wildcard)
sc.Has("billing:write")   // true (wildcard)
sc.Has("inventory:read")  // true (exact)
sc.Has("inventory:write") // false
```

## Middleware

### Gin

```go
auth := oryxid.NewGinMiddleware(client)

// Require valid token
r.Use(auth.Protect())

// Require specific scope
r.GET("/billing", auth.RequireScope("billing:read"), handler)

// Require any of scopes
r.GET("/admin", auth.RequireScopeAny("admin", "superuser"), handler)

// Access claims
func handler(c *gin.Context) {
    claims := oryxid.GetGinClaims(c)
}
```

### Standard HTTP

```go
mw := oryxid.NewMiddleware(client)

mux.Handle("/api/data", mw.RequireScope("data:read")(handler))

func handler(w http.ResponseWriter, r *http.Request) {
    claims := oryxid.GetClaims(r)
}
```

## Configuration

```go
client, err := oryxid.New(oryxid.Config{
    IssuerURL:    "https://auth.example.com",  // Required
    ClientID:     "my-api",                    // For introspection
    ClientSecret: "secret",                    // For introspection
    JWKSCacheTTL: time.Hour,                   // Default: 1 hour
    HTTPClient:   customClient,                // Optional
})
```

## Scope Patterns

| Token Scope | Required Scope | Match |
| ------------- | ---------------- | ------- |
| `billing:read` | `billing:read` | Yes |
| `billing:read` | `billing:write` | No |
| `billing:*` | `billing:read` | Yes |
| `billing:*` | `billing:write` | Yes |
| `*` | `anything` | Yes |
