package subdomain

import (
	"testing"
)

func TestCleanSubdomain(t *testing.T) {
	tests := []struct {
		sub        string
		baseDomain string
		expected   string
	}{
		{"*.example.com", "example.com", "example.com"},
		{"www.example.com.", "example.com", "www.example.com"},
		{"  API.EXAMPLE.COM  ", "example.com", "api.example.com"},
		{"other.domain.com", "example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.sub, func(t *testing.T) {
			result := cleanSubdomain(tt.sub, tt.baseDomain)
			if result != tt.expected {
				t.Errorf("cleanSubdomain(%s, %s) = %s, expected %s", tt.sub, tt.baseDomain, result, tt.expected)
			}
		})
	}
}

func TestIsValidSubdomain(t *testing.T) {
	tests := []struct {
		sub        string
		baseDomain string
		expected   bool
	}{
		{"www.example.com", "example.com", true},
		{"api.example.com", "example.com", true},
		{"example.com", "example.com", false},
		{"*.example.com", "example.com", false},
		{"other.domain.com", "example.com", false},
		{"sub domain.example.com", "example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.sub, func(t *testing.T) {
			result := isValidSubdomain(tt.sub, tt.baseDomain)
			if result != tt.expected {
				t.Errorf("isValidSubdomain(%s, %s) = %v, expected %v", tt.sub, tt.baseDomain, result, tt.expected)
			}
		})
	}
}

func TestRemoveDuplicates(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b", "d"}
	expected := []string{"a", "b", "c", "d"}

	result := removeDuplicates(input)

	if len(result) != len(expected) {
		t.Errorf("Expected %d items, got %d", len(expected), len(result))
	}

	for i, v := range expected {
		if result[i] != v {
			t.Errorf("Expected %s at index %d, got %s", v, i, result[i])
		}
	}
}

func TestCommonSubdomainPrefixes(t *testing.T) {
	prefixes := CommonSubdomainPrefixes()

	if len(prefixes) == 0 {
		t.Error("Expected non-empty list of common prefixes")
	}

	expectedPrefixes := []string{"www", "mail", "api", "admin", "dev"}
	for _, expected := range expectedPrefixes {
		found := false
		for _, prefix := range prefixes {
			if prefix == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected prefix '%s' not found in common prefixes", expected)
		}
	}
}
