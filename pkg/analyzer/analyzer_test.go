package analyzer

import (
	"testing"

	"netanalyze/pkg/types"
)

func TestAnalyzeTLS(t *testing.T) {
	tests := []struct {
		name    string
		tls     types.TLSInfo
		grade   types.SSLGrade
		wantSev string
		wantMsg string
	}{
		{
			name: "TLS 1.3 Positive",
			tls: types.TLSInfo{
				Version: "TLS 1.3",
			},
			grade: types.SSLGrade{
				Grade: "A+",
			},
			wantSev: "positive",
			wantMsg: "Using modern TLS 1.3 protocol",
		},
		{
			name: "TLS 1.2 Info",
			tls: types.TLSInfo{
				Version: "TLS 1.2",
			},
			grade: types.SSLGrade{
				Grade: "A",
			},
			wantSev: "info",
			wantMsg: "Using TLS 1.2 (consider upgrading to TLS 1.3)",
		},
		{
			name: "Expired Certificate",
			tls: types.TLSInfo{
				Version: "TLS 1.2",
			},
			grade: types.SSLGrade{
				Grade:           "F",
				CertExpiresDays: -1,
			},
			wantSev: "critical",
			wantMsg: "SSL Certificate EXPIRED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeTLS(tt.tls, tt.grade)
			found := false
			for _, f := range findings {
				if f.Message == tt.wantMsg {
					found = true
					if f.Severity != tt.wantSev {
						t.Errorf("analyzeTLS() severity = %v, want %v", f.Severity, tt.wantSev)
					}
				}
			}
			if !found {
				t.Errorf("analyzeTLS() finding not found: %v", tt.wantMsg)
			}
		})
	}
}

func TestAnalyzeHTTP(t *testing.T) {
	tests := []struct {
		name    string
		http    types.HTTPInfo
		wantSev string
		wantMsg string
	}{
		{
			name: "Missing Security Headers",
			http: types.HTTPInfo{
				SecurityHeaders: map[string]string{
					"Strict-Transport-Security": "Not Set",
				},
			},
			wantSev: "warning",
			wantMsg: "Missing security headers: HSTS",
		},
		{
			name: "HTTP/3 Detected",
			http: types.HTTPInfo{
				TechStack: types.TechFingerprint{
					HTTPVersion: "HTTP/3",
				},
				SecurityHeaders: map[string]string{},
			},
			wantSev: "positive",
			wantMsg: "Using HTTP/3 (QUIC) protocol",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := analyzeHTTP(tt.http)
			found := false
			for _, f := range findings {
				if f.Message == tt.wantMsg {
					found = true
					if f.Severity != tt.wantSev {
						t.Errorf("analyzeHTTP() severity = %v, want %v", f.Severity, tt.wantSev)
					}
				}
			}
			if !found {
				t.Errorf("analyzeHTTP() finding not found: %v", tt.wantMsg)
			}
		})
	}
}
