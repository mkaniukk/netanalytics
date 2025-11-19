package tls

import (
	"crypto/tls"
	"testing"

	"netanalyze/pkg/types"
)

func TestTlsVersion(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{tls.VersionTLS13, "TLS 1.3"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS10, "TLS 1.0"},
		{0x0300, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tlsVersion(tt.version); got != tt.want {
				t.Errorf("tlsVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGradeSSL(t *testing.T) {
	tests := []struct {
		name      string
		tlsInfo   types.TLSInfo
		wantGrade string
	}{
		{
			name: "Perfect Score",
			tlsInfo: types.TLSInfo{
				Version:     "TLS 1.3",
				CipherSuite: "TLS_AES_256_GCM_SHA384",
				KeyType:     "RSA 4096 bits",
				Expiry:      "2030-01-01 12:00:00 +0000 UTC",
			},
			wantGrade: "A+",
		},
		{
			name: "Good Score",
			tlsInfo: types.TLSInfo{
				Version:     "TLS 1.3",
				CipherSuite: "TLS_AES_128_GCM_SHA256",
				KeyType:     "RSA 2048 bits",
				Expiry:      "2030-01-01 12:00:00 +0000 UTC",
			},
			wantGrade: "A+",
		},
		{
			name: "TLS 1.2",
			tlsInfo: types.TLSInfo{
				Version:     "TLS 1.2",
				CipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				KeyType:     "RSA 2048 bits",
				Expiry:      "2030-01-01 12:00:00 +0000 UTC",
			},
			wantGrade: "A",
		},
		{
			name: "Weak Key",
			tlsInfo: types.TLSInfo{
				Version:     "TLS 1.2",
				CipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				KeyType:     "RSA 1024 bits",
				Expiry:      "2030-01-01 12:00:00 +0000 UTC",
			},
			wantGrade: "D",
		},
		{
			name: "Expired Cert",
			tlsInfo: types.TLSInfo{
				Version:     "TLS 1.3",
				CipherSuite: "TLS_AES_256_GCM_SHA384",
				KeyType:     "RSA 2048 bits",
				Expiry:      "2020-01-01 12:00:00 +0000 UTC",
			},
			wantGrade: "F",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GradeSSL(tt.tlsInfo)
			if got.Grade != tt.wantGrade {
				t.Errorf("GradeSSL() grade = %v, want %v (Score: %d, Issues: %v)", got.Grade, tt.wantGrade, got.Score, got.Issues)
			}
		})
	}
}
