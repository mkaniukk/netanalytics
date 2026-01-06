package whois

import (
	"testing"
)

func TestCalculateDomainAge(t *testing.T) {
	tests := []struct {
		raw      string
		hasValue bool
	}{
		{"2024-01-15T12:00:00Z", true},
		{"2024-01-15", true},
		{"invalid-date", false},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			result := calculateDomainAge(tt.raw)
			if tt.hasValue && result == "" {
				t.Errorf("Expected non-empty result for %s, got empty", tt.raw)
			}
			if !tt.hasValue && result != "" {
				t.Errorf("Expected empty result for %s, got %s", tt.raw, result)
			}
		})
	}
}

func TestContains(t *testing.T) {
	slice := []string{"a", "b", "c"}

	if !contains(slice, "a") {
		t.Error("Expected to find 'a' in slice")
	}

	if contains(slice, "d") {
		t.Error("Did not expect to find 'd' in slice")
	}
}

func TestParseWhoisResponse(t *testing.T) {
	sampleResponse := `
Domain Name: EXAMPLE.COM
Registrar: Example Registrar Inc.
Creation Date: 2010-01-15T00:00:00Z
Registry Expiry Date: 2025-01-15T00:00:00Z
Updated Date: 2024-01-15T00:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
Domain Status: clientTransferProhibited
`

	info := parseWhoisResponse(sampleResponse)

	if info.Registrar != "Example Registrar Inc." {
		t.Errorf("Expected registrar 'Example Registrar Inc.', got '%s'", info.Registrar)
	}

	if info.CreationDate != "2010-01-15T00:00:00Z" {
		t.Errorf("Expected creation date '2010-01-15T00:00:00Z', got '%s'", info.CreationDate)
	}

	if len(info.NameServers) != 2 {
		t.Errorf("Expected 2 name servers, got %d", len(info.NameServers))
	}

	if len(info.DomainStatus) == 0 {
		t.Error("Expected at least one domain status")
	}
}
