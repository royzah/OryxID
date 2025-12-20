package oryxid

import "strings"

// ScopeChecker provides scope validation with hierarchy support.
type ScopeChecker struct {
	scopes map[string]struct{}
}

// NewScopeChecker creates a ScopeChecker from a space-separated scope string.
func NewScopeChecker(scopeString string) *ScopeChecker {
	sc := &ScopeChecker{
		scopes: make(map[string]struct{}),
	}
	for _, s := range strings.Fields(scopeString) {
		sc.scopes[s] = struct{}{}
	}
	return sc
}

// NewScopeCheckerFromSlice creates a ScopeChecker from a slice of scopes.
func NewScopeCheckerFromSlice(scopes []string) *ScopeChecker {
	sc := &ScopeChecker{
		scopes: make(map[string]struct{}),
	}
	for _, s := range scopes {
		sc.scopes[s] = struct{}{}
	}
	return sc
}

// Has checks if the required scope is present.
// Supports wildcard matching:
//   - "billing:*" matches "billing:read", "billing:write", etc.
//   - "billing:read" matches exactly "billing:read"
//   - "*" matches anything
func (sc *ScopeChecker) Has(required string) bool {
	// Direct match
	if _, ok := sc.scopes[required]; ok {
		return true
	}

	// Check for wildcard in token scopes
	if _, ok := sc.scopes["*"]; ok {
		return true
	}

	// Check for prefix wildcard (e.g., token has "billing:*")
	parts := strings.Split(required, ":")
	if len(parts) > 1 {
		prefix := parts[0] + ":*"
		if _, ok := sc.scopes[prefix]; ok {
			return true
		}
	}

	return false
}

// HasAny checks if any of the required scopes is present.
func (sc *ScopeChecker) HasAny(required ...string) bool {
	for _, r := range required {
		if sc.Has(r) {
			return true
		}
	}
	return false
}

// HasAll checks if all required scopes are present.
func (sc *ScopeChecker) HasAll(required ...string) bool {
	for _, r := range required {
		if !sc.Has(r) {
			return false
		}
	}
	return true
}

// List returns all scopes as a slice.
func (sc *ScopeChecker) List() []string {
	result := make([]string, 0, len(sc.scopes))
	for s := range sc.scopes {
		result = append(result, s)
	}
	return result
}

// CheckScope is a convenience function to check a single scope.
func CheckScope(scopeString, required string) bool {
	return NewScopeChecker(scopeString).Has(required)
}

// CheckScopes is a convenience function to check multiple scopes.
func CheckScopes(scopeString string, required ...string) bool {
	return NewScopeChecker(scopeString).HasAll(required...)
}

// CheckScopesAny is a convenience function to check if any scope matches.
func CheckScopesAny(scopeString string, required ...string) bool {
	return NewScopeChecker(scopeString).HasAny(required...)
}
