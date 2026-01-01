package oauth

import (
	"strings"
)

// ScopeHierarchy defines scope implications
// Key scope implies all value scopes
var ScopeHierarchy = map[string][]string{
	// TrustSky USSP scope hierarchy
	"trustsky:admin": {
		"trustsky:flight:read",
		"trustsky:flight:write",
		"trustsky:nfz:read",
		"trustsky:nfz:write",
		"trustsky:telemetry:write",
		"trustsky:sky:read",
		"trustsky:operator:read",
		"trustsky:operator:write",
	},
	"trustsky:flight:write":   {"trustsky:flight:read"},
	"trustsky:nfz:write":      {"trustsky:nfz:read"},
	"trustsky:operator:write": {"trustsky:operator:read"},
}

// ExpandScopes expands a scope string according to the hierarchy rules
// For example, "trustsky:admin" expands to include all trustsky:* scopes
func ExpandScopes(scopeStr string) string {
	if scopeStr == "" {
		return ""
	}

	scopes := strings.Split(scopeStr, " ")
	expandedSet := make(map[string]bool)

	// Add original scopes
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			expandedSet[scope] = true
			// Expand hierarchical scopes
			expandScope(scope, expandedSet)
		}
	}

	// Convert back to space-separated string
	result := make([]string, 0, len(expandedSet))
	for scope := range expandedSet {
		result = append(result, scope)
	}

	return strings.Join(result, " ")
}

// expandScope recursively expands a single scope according to hierarchy
func expandScope(scope string, expandedSet map[string]bool) {
	// Check direct hierarchy mapping
	if impliedScopes, exists := ScopeHierarchy[scope]; exists {
		for _, implied := range impliedScopes {
			if !expandedSet[implied] {
				expandedSet[implied] = true
				// Recursively expand (in case of nested hierarchy)
				expandScope(implied, expandedSet)
			}
		}
	}
}

// HasScope checks if the granted scopes include the required scope
// Supports both exact match and hierarchical matching
func HasScope(grantedScopesStr, requiredScope string) bool {
	if grantedScopesStr == "" || requiredScope == "" {
		return false
	}

	// First expand granted scopes according to hierarchy
	expanded := ExpandScopes(grantedScopesStr)
	expandedScopes := strings.Split(expanded, " ")

	for _, scope := range expandedScopes {
		if scope == requiredScope {
			return true
		}
	}

	return false
}

// HasAnyScope checks if granted scopes include any of the required scopes
func HasAnyScope(grantedScopesStr string, requiredScopes []string) bool {
	for _, required := range requiredScopes {
		if HasScope(grantedScopesStr, required) {
			return true
		}
	}
	return false
}

// HasAllScopes checks if granted scopes include all of the required scopes
func HasAllScopes(grantedScopesStr string, requiredScopes []string) bool {
	for _, required := range requiredScopes {
		if !HasScope(grantedScopesStr, required) {
			return false
		}
	}
	return true
}

// FilterValidScopes filters requested scopes against allowed scopes
// Returns only scopes that are allowed (considering hierarchy)
func FilterValidScopes(requestedScopesStr string, allowedScopes map[string]bool) string {
	if requestedScopesStr == "" {
		return ""
	}

	requested := strings.Split(requestedScopesStr, " ")
	valid := make([]string, 0)

	for _, scope := range requested {
		scope = strings.TrimSpace(scope)
		if scope != "" && allowedScopes[scope] {
			valid = append(valid, scope)
		}
	}

	return strings.Join(valid, " ")
}

// NormalizeScopes removes duplicates and sorts scopes consistently
func NormalizeScopes(scopeStr string) string {
	if scopeStr == "" {
		return ""
	}

	scopes := strings.Split(scopeStr, " ")
	scopeSet := make(map[string]bool)

	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			scopeSet[scope] = true
		}
	}

	result := make([]string, 0, len(scopeSet))
	for scope := range scopeSet {
		result = append(result, scope)
	}

	return strings.Join(result, " ")
}
