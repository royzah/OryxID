package oryxid

import (
	"context"
	"net/http"
)

// ContextKey is the type for context keys.
type ContextKey string

const (
	// ClaimsKey is the context key for JWT claims.
	ClaimsKey ContextKey = "oryxid_claims"
)

// Middleware provides HTTP middleware for token validation.
type Middleware struct {
	client *Client
}

// NewMiddleware creates a new middleware instance.
func NewMiddleware(client *Client) *Middleware {
	return &Middleware{
		client: client,
	}
}

// Protect returns middleware that requires a valid token.
func (m *Middleware) Protect() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ExtractToken(r.Header.Get("Authorization"))
			if token == "" {
				http.Error(w, `{"error":"missing_token"}`, http.StatusUnauthorized)
				return
			}

			claims, err := m.client.ValidateJWT(token)
			if err != nil {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScope returns middleware that requires specific scopes.
func (m *Middleware) RequireScope(required ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ExtractToken(r.Header.Get("Authorization"))
			if token == "" {
				http.Error(w, `{"error":"missing_token"}`, http.StatusUnauthorized)
				return
			}

			claims, err := m.client.ValidateJWT(token)
			if err != nil {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			sc := NewScopeChecker(claims.Scope)
			if !sc.HasAll(required...) {
				http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireScopeAny returns middleware that requires any of the specified scopes.
func (m *Middleware) RequireScopeAny(required ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ExtractToken(r.Header.Get("Authorization"))
			if token == "" {
				http.Error(w, `{"error":"missing_token"}`, http.StatusUnauthorized)
				return
			}

			claims, err := m.client.ValidateJWT(token)
			if err != nil {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			sc := NewScopeChecker(claims.Scope)
			if !sc.HasAny(required...) {
				http.Error(w, `{"error":"insufficient_scope"}`, http.StatusForbidden)
				return
			}

			ctx := context.WithValue(r.Context(), ClaimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClaims retrieves the claims from the request context.
func GetClaims(r *http.Request) *Claims {
	claims, ok := r.Context().Value(ClaimsKey).(*Claims)
	if !ok {
		return nil
	}
	return claims
}

// GetClaimsFromContext retrieves the claims from a context.
func GetClaimsFromContext(ctx context.Context) *Claims {
	claims, ok := ctx.Value(ClaimsKey).(*Claims)
	if !ok {
		return nil
	}
	return claims
}
