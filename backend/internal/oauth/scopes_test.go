package oauth

import (
	"strings"
	"testing"
)

func TestExpandScopes(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string // Expected scopes (order doesn't matter)
	}{
		{
			name:     "empty scope",
			input:    "",
			expected: nil,
		},
		{
			name:     "single scope no expansion",
			input:    "openid",
			expected: []string{"openid"},
		},
		{
			name:     "flight write expands to read",
			input:    "trustsky:flight:write",
			expected: []string{"trustsky:flight:write", "trustsky:flight:read"},
		},
		{
			name:     "nfz write expands to read",
			input:    "trustsky:nfz:write",
			expected: []string{"trustsky:nfz:write", "trustsky:nfz:read"},
		},
		{
			name:     "admin expands to all trustsky scopes",
			input:    "trustsky:admin",
			expected: []string{
				"trustsky:admin",
				"trustsky:flight:read",
				"trustsky:flight:write",
				"trustsky:nfz:read",
				"trustsky:nfz:write",
				"trustsky:telemetry:write",
				"trustsky:sky:read",
				"trustsky:operator:read",
				"trustsky:operator:write",
			},
		},
		{
			name:     "multiple scopes with partial expansion",
			input:    "openid profile trustsky:flight:write",
			expected: []string{"openid", "profile", "trustsky:flight:write", "trustsky:flight:read"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ExpandScopes(tt.input)

			if tt.expected == nil {
				if result != "" {
					t.Errorf("expected empty string, got %q", result)
				}
				return
			}

			resultScopes := strings.Split(result, " ")
			if len(resultScopes) != len(tt.expected) {
				t.Errorf("expected %d scopes, got %d: %v", len(tt.expected), len(resultScopes), resultScopes)
				return
			}

			resultSet := make(map[string]bool)
			for _, s := range resultScopes {
				resultSet[s] = true
			}

			for _, expected := range tt.expected {
				if !resultSet[expected] {
					t.Errorf("expected scope %q not found in result: %v", expected, resultScopes)
				}
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	tests := []struct {
		name     string
		granted  string
		required string
		expected bool
	}{
		{
			name:     "empty granted",
			granted:  "",
			required: "openid",
			expected: false,
		},
		{
			name:     "exact match",
			granted:  "openid profile",
			required: "openid",
			expected: true,
		},
		{
			name:     "admin has flight read via hierarchy",
			granted:  "trustsky:admin",
			required: "trustsky:flight:read",
			expected: true,
		},
		{
			name:     "admin has flight write via hierarchy",
			granted:  "trustsky:admin",
			required: "trustsky:flight:write",
			expected: true,
		},
		{
			name:     "flight write has flight read via hierarchy",
			granted:  "trustsky:flight:write",
			required: "trustsky:flight:read",
			expected: true,
		},
		{
			name:     "flight read does not have flight write",
			granted:  "trustsky:flight:read",
			required: "trustsky:flight:write",
			expected: false,
		},
		{
			name:     "unrelated scope not granted",
			granted:  "openid profile",
			required: "trustsky:admin",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasScope(tt.granted, tt.required)
			if result != tt.expected {
				t.Errorf("HasScope(%q, %q) = %v, expected %v", tt.granted, tt.required, result, tt.expected)
			}
		})
	}
}

func TestHasAllScopes(t *testing.T) {
	tests := []struct {
		name     string
		granted  string
		required []string
		expected bool
	}{
		{
			name:     "admin has all flight scopes",
			granted:  "trustsky:admin",
			required: []string{"trustsky:flight:read", "trustsky:flight:write"},
			expected: true,
		},
		{
			name:     "missing one scope",
			granted:  "trustsky:flight:read",
			required: []string{"trustsky:flight:read", "trustsky:flight:write"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasAllScopes(tt.granted, tt.required)
			if result != tt.expected {
				t.Errorf("HasAllScopes(%q, %v) = %v, expected %v", tt.granted, tt.required, result, tt.expected)
			}
		})
	}
}
