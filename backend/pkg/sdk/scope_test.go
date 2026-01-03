package oryxid

import "testing"

func TestScopeChecker_Has(t *testing.T) {
	tests := []struct {
		name     string
		scopes   string
		required string
		want     bool
	}{
		{
			name:     "exact match",
			scopes:   "billing:read billing:write",
			required: "billing:read",
			want:     true,
		},
		{
			name:     "no match",
			scopes:   "billing:read",
			required: "billing:write",
			want:     false,
		},
		{
			name:     "wildcard in token matches specific",
			scopes:   "billing:*",
			required: "billing:read",
			want:     true,
		},
		{
			name:     "wildcard in token matches any action",
			scopes:   "billing:*",
			required: "billing:delete",
			want:     true,
		},
		{
			name:     "global wildcard matches anything",
			scopes:   "*",
			required: "anything:here",
			want:     true,
		},
		{
			name:     "specific scope does not match wildcard requirement",
			scopes:   "billing:read",
			required: "billing:*",
			want:     false,
		},
		{
			name:     "different prefix no match",
			scopes:   "billing:*",
			required: "inventory:read",
			want:     false,
		},
		{
			name:     "simple scope without colon",
			scopes:   "admin read write",
			required: "admin",
			want:     true,
		},
		{
			name:     "empty scopes",
			scopes:   "",
			required: "billing:read",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := NewScopeChecker(tt.scopes)
			if got := sc.Has(tt.required); got != tt.want {
				t.Errorf("ScopeChecker.Has() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScopeChecker_HasAll(t *testing.T) {
	tests := []struct {
		name     string
		scopes   string
		required []string
		want     bool
	}{
		{
			name:     "has all exact",
			scopes:   "billing:read billing:write inventory:read",
			required: []string{"billing:read", "billing:write"},
			want:     true,
		},
		{
			name:     "missing one",
			scopes:   "billing:read",
			required: []string{"billing:read", "billing:write"},
			want:     false,
		},
		{
			name:     "wildcard covers all",
			scopes:   "billing:*",
			required: []string{"billing:read", "billing:write"},
			want:     true,
		},
		{
			name:     "wildcard partial cover",
			scopes:   "billing:*",
			required: []string{"billing:read", "inventory:read"},
			want:     false,
		},
		{
			name:     "empty required",
			scopes:   "billing:read",
			required: []string{},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := NewScopeChecker(tt.scopes)
			if got := sc.HasAll(tt.required...); got != tt.want {
				t.Errorf("ScopeChecker.HasAll() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScopeChecker_HasAny(t *testing.T) {
	tests := []struct {
		name     string
		scopes   string
		required []string
		want     bool
	}{
		{
			name:     "has one",
			scopes:   "billing:read",
			required: []string{"billing:read", "billing:write"},
			want:     true,
		},
		{
			name:     "has none",
			scopes:   "inventory:read",
			required: []string{"billing:read", "billing:write"},
			want:     false,
		},
		{
			name:     "wildcard matches one",
			scopes:   "billing:*",
			required: []string{"billing:read", "inventory:read"},
			want:     true,
		},
		{
			name:     "empty required",
			scopes:   "billing:read",
			required: []string{},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sc := NewScopeChecker(tt.scopes)
			if got := sc.HasAny(tt.required...); got != tt.want {
				t.Errorf("ScopeChecker.HasAny() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckScope(t *testing.T) {
	if !CheckScope("billing:read billing:write", "billing:read") {
		t.Error("CheckScope should return true")
	}
	if CheckScope("billing:read", "billing:write") {
		t.Error("CheckScope should return false")
	}
}
