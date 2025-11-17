package tls

import (
	"crypto/rsa"
	cryptotls "crypto/tls"
	"fmt"
	"strings"
	"time"

	"netanalyze/pkg/types"
)

func tlsVersion(v uint16) string {
	switch v {
	case cryptotls.VersionTLS13:
		return "TLS 1.3"
	case cryptotls.VersionTLS12:
		return "TLS 1.2"
	default:
		return "Unknown"
	}
}

func AnalyzeTLS(host string) types.TLSInfo {
	info := types.TLSInfo{}
	conn, err := cryptotls.Dial("tcp", host+":443", &cryptotls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
	})
	if err != nil {
		return info
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info.Version = tlsVersion(state.Version)
	info.CipherSuite = cryptotls.CipherSuiteName(state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Issuer = cert.Issuer.CommonName
		info.Subject = cert.Subject.CommonName
		info.Expiry = cert.NotAfter.String()
		info.NotBefore = cert.NotBefore.String()
		info.SignatureAlgo = cert.SignatureAlgorithm.String()
		info.PublicKeyAlgo = cert.PublicKeyAlgorithm.String()
		info.SAN = append(info.SAN, cert.DNSNames...)
		info.SerialNumber = cert.SerialNumber.String()
		info.ChainLength = len(state.PeerCertificates)
		info.OCSPStapling = len(state.OCSPResponse) > 0

		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			info.KeySize = pub.Size() * 8
			info.KeyType = fmt.Sprintf("RSA %d bits", info.KeySize)
		} else {
			info.KeyType = info.PublicKeyAlgo
		}

		// Cipher strength analysis
		if strings.Contains(info.CipherSuite, "AES_256") {
			info.CipherStrength = "256-bit"
		} else if strings.Contains(info.CipherSuite, "AES_128") {
			info.CipherStrength = "128-bit"
		} else if strings.Contains(info.CipherSuite, "CHACHA20") {
			info.CipherStrength = "256-bit"
		}

		// Key exchange mechanism
		if strings.Contains(info.CipherSuite, "ECDHE") {
			info.KeyExchange = "ECDHE (Forward Secrecy)"
		} else if strings.Contains(info.CipherSuite, "DHE") {
			info.KeyExchange = "DHE (Forward Secrecy)"
		} else if info.Version == "TLS 1.3" {
			info.KeyExchange = "TLS 1.3 (Perfect Forward Secrecy)"
		}
	}
	return info
}

func GradeSSL(tlsInfo types.TLSInfo) types.SSLGrade {
	grade := types.SSLGrade{Score: 100}

	if tlsInfo.Expiry != "" {
		if expiry, err := time.Parse("2006-01-02 15:04:05 -0700 MST", tlsInfo.Expiry); err == nil {
			daysUntil := int(time.Until(expiry).Hours() / 24)
			grade.CertExpiresDays = daysUntil
			if daysUntil < 0 {
				grade.Score = 0
				grade.Issues = append(grade.Issues, "Certificate EXPIRED")
			} else if daysUntil < 7 {
				grade.Score -= 50
				grade.Issues = append(grade.Issues, fmt.Sprintf("Certificate expires in %d days", daysUntil))
			} else if daysUntil < 30 {
				grade.Score -= 20
				grade.Issues = append(grade.Issues, fmt.Sprintf("Certificate expires soon (%d days)", daysUntil))
			}
		}
	}

	switch tlsInfo.Version {
	case "TLS 1.3":
		grade.Strengths = append(grade.Strengths, "TLS 1.3 support")
	case "TLS 1.2":
		grade.Score -= 10
		grade.Issues = append(grade.Issues, "TLS 1.2 only (consider TLS 1.3)")
	default:
		grade.Score -= 40
		grade.Issues = append(grade.Issues, "Outdated TLS version")
	}

	if strings.Contains(tlsInfo.CipherSuite, "AES_256_GCM") {
		grade.Strengths = append(grade.Strengths, "Strong cipher (AES-256-GCM)")
	} else if strings.Contains(tlsInfo.CipherSuite, "AES_128_GCM") {
		grade.Strengths = append(grade.Strengths, "Good cipher (AES-128-GCM)")
	} else if strings.Contains(tlsInfo.CipherSuite, "CBC") {
		grade.Score -= 15
		grade.Issues = append(grade.Issues, "CBC mode cipher (consider GCM)")
	}

	if strings.Contains(tlsInfo.KeyType, "RSA 2048") {
		grade.Strengths = append(grade.Strengths, "RSA 2048-bit key")
	} else if strings.Contains(tlsInfo.KeyType, "RSA 4096") {
		grade.Strengths = append(grade.Strengths, "RSA 4096-bit key")
	} else if strings.Contains(tlsInfo.KeyType, "RSA") && strings.Contains(tlsInfo.KeyType, "1024") {
		grade.Score -= 30
		grade.Issues = append(grade.Issues, "Weak RSA key (1024-bit)")
	}

	switch {
	case grade.Score >= 95:
		grade.Grade = "A+"
	case grade.Score >= 90:
		grade.Grade = "A"
	case grade.Score >= 80:
		grade.Grade = "B"
	case grade.Score >= 70:
		grade.Grade = "C"
	case grade.Score >= 50:
		grade.Grade = "D"
	default:
		grade.Grade = "F"
	}
	return grade
}
