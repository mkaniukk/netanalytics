package analyzer

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"netanalyze/pkg/types"
)

// AnalyzeFindings examines the analysis results and identifies important/unusual findings
func AnalyzeFindings(result *types.AnalysisResult) []types.Finding {
	var findings []types.Finding

	// TLS/SSL Security Analysis
	if result.TLS.Version != "" {
		findings = append(findings, analyzeTLS(result.TLS, result.SSLGrade)...)
	}

	// HTTP Security Headers
	if result.HTTP.Status != 0 {
		findings = append(findings, analyzeHTTP(result.HTTP)...)
	}

	// Performance Issues
	if result.Performance.TotalTime != "" {
		findings = append(findings, analyzePerformance(result.Performance)...)
	}

	// Infrastructure Detection
	findings = append(findings, analyzeInfrastructure(result)...)

	// DNS Configuration
	if len(result.DNS.A) > 0 || len(result.DNS.AAAA) > 0 {
		findings = append(findings, analyzeDNS(result.DNS)...)
	}

	// Port Security
	if len(result.Ports) > 0 {
		findings = append(findings, analyzePorts(result.Ports)...)
	}

	return findings
}

func analyzeTLS(tls types.TLSInfo, grade types.SSLGrade) []types.Finding {
	var findings []types.Finding

	// Certificate expiration
	if grade.CertExpiresDays > 0 && grade.CertExpiresDays < 30 {
		findings = append(findings, types.Finding{
			Severity: "warning",
			Category: "Security",
			Message:  fmt.Sprintf("Certificate expires in %d days", grade.CertExpiresDays),
			Detail:   "Consider renewing your SSL certificate soon to avoid service disruption",
		})
	} else if grade.CertExpiresDays < 0 {
		findings = append(findings, types.Finding{
			Severity: "critical",
			Category: "Security",
			Message:  "SSL Certificate EXPIRED",
			Detail:   "The SSL certificate has expired. This is a critical security issue.",
		})
	}

	// TLS version
	if tls.Version == "TLS 1.3" {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Security",
			Message:  "Using modern TLS 1.3 protocol",
			Detail:   "TLS 1.3 provides improved security and performance",
		})
	} else if tls.Version == "TLS 1.2" {
		findings = append(findings, types.Finding{
			Severity: "info",
			Category: "Security",
			Message:  "Using TLS 1.2 (consider upgrading to TLS 1.3)",
			Detail:   "TLS 1.2 is secure but TLS 1.3 offers better performance and security",
		})
	} else if tls.Version != "" {
		findings = append(findings, types.Finding{
			Severity: "warning",
			Category: "Security",
			Message:  fmt.Sprintf("Outdated TLS version: %s", tls.Version),
			Detail:   "Using an outdated TLS version poses security risks",
		})
	}

	// Forward Secrecy
	if strings.Contains(tls.KeyExchange, "Perfect Forward Secrecy") {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Security",
			Message:  "Perfect Forward Secrecy enabled",
			Detail:   "Protects past sessions against future compromises of secret keys",
		})
	}

	// Cipher strength
	if tls.CipherStrength == "256-bit" {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Security",
			Message:  "Strong 256-bit encryption",
			Detail:   "Using industry-standard strong encryption",
		})
	}

	// SSL Grade
	if grade.Grade == "A+" || grade.Grade == "A" {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Security",
			Message:  fmt.Sprintf("Excellent SSL configuration (Grade: %s)", grade.Grade),
			Detail:   fmt.Sprintf("SSL Labs grade: %s with score %d/100", grade.Grade, grade.Score),
		})
	} else if grade.Grade == "B" || grade.Grade == "C" {
		findings = append(findings, types.Finding{
			Severity: "warning",
			Category: "Security",
			Message:  fmt.Sprintf("SSL configuration needs improvement (Grade: %s)", grade.Grade),
			Detail:   fmt.Sprintf("Current score: %d/100. Review SSL configuration for security improvements", grade.Score),
		})
	} else if grade.Grade != "" {
		findings = append(findings, types.Finding{
			Severity: "critical",
			Category: "Security",
			Message:  fmt.Sprintf("Poor SSL configuration (Grade: %s)", grade.Grade),
			Detail:   fmt.Sprintf("Critical security issues detected. Score: %d/100", grade.Score),
		})
	}

	return findings
}

func analyzeHTTP(http types.HTTPInfo) []types.Finding {
	var findings []types.Finding

	// Security Headers
	missingHeaders := []string{}
	if http.SecurityHeaders["Strict-Transport-Security"] == "Not Set" {
		missingHeaders = append(missingHeaders, "HSTS")
	}
	if http.SecurityHeaders["Content-Security-Policy"] == "Not Set" {
		missingHeaders = append(missingHeaders, "CSP")
	}
	if http.SecurityHeaders["X-Content-Type-Options"] == "Not Set" {
		missingHeaders = append(missingHeaders, "X-Content-Type-Options")
	}

	if len(missingHeaders) > 0 {
		findings = append(findings, types.Finding{
			Severity: "warning",
			Category: "Security",
			Message:  fmt.Sprintf("Missing security headers: %s", strings.Join(missingHeaders, ", ")),
			Detail:   "These headers provide additional security protection against common attacks",
		})
	}

	// HTTP/3 Detection
	if strings.Contains(http.TechStack.HTTPVersion, "HTTP/3") || strings.Contains(http.TechStack.HTTPVersion, "h3") {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Performance",
			Message:  "Using HTTP/3 (QUIC) protocol",
			Detail:   "Modern protocol providing improved performance and reliability",
		})
	} else if strings.Contains(http.TechStack.HTTPVersion, "HTTP/2") || strings.Contains(http.TechStack.HTTPVersion, "h2") {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Performance",
			Message:  "Using HTTP/2 protocol",
			Detail:   "Modern protocol with multiplexing and header compression",
		})
	}

	// Redirects
	if len(http.RedirectChain) > 3 {
		findings = append(findings, types.Finding{
			Severity: "warning",
			Category: "Performance",
			Message:  fmt.Sprintf("Excessive redirects: %d hops", len(http.RedirectChain)),
			Detail:   "Multiple redirects increase page load time and affect user experience",
		})
	}

	// Technology Stack
	if len(http.Technology) > 0 {
		findings = append(findings, types.Finding{
			Severity: "info",
			Category: "Configuration",
			Message:  fmt.Sprintf("Detected technologies: %s", strings.Join(http.Technology, ", ")),
			Detail:   "Technology fingerprinting can help identify potential security updates needed",
		})
	}

	return findings
}

func analyzePerformance(perf types.PerformanceInfo) []types.Finding {
	var findings []types.Finding

	// Parse TLS handshake time
	if perf.TLSHandshake != "" {
		if duration, err := time.ParseDuration(perf.TLSHandshake); err == nil {
			if duration > 500*time.Millisecond {
				findings = append(findings, types.Finding{
					Severity: "warning",
					Category: "Performance",
					Message:  fmt.Sprintf("Slow TLS handshake: %s", perf.TLSHandshake),
					Detail:   "TLS handshake taking longer than expected, may affect user experience",
				})
			}
		}
	}

	// Parse total time
	if perf.TotalTime != "" {
		if duration, err := time.ParseDuration(perf.TotalTime); err == nil {
			if duration > 2*time.Second {
				findings = append(findings, types.Finding{
					Severity: "warning",
					Category: "Performance",
					Message:  fmt.Sprintf("Slow response time: %s", perf.TotalTime),
					Detail:   "Total response time exceeds recommended threshold",
				})
			} else if duration < 200*time.Millisecond {
				findings = append(findings, types.Finding{
					Severity: "positive",
					Category: "Performance",
					Message:  fmt.Sprintf("Excellent response time: %s", perf.TotalTime),
					Detail:   "Fast response time provides good user experience",
				})
			}
		}
	}

	return findings
}

func analyzeInfrastructure(result *types.AnalysisResult) []types.Finding {
	var findings []types.Finding

	// CDN Detection
	if result.CDN.Detected {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Infrastructure",
			Message:  fmt.Sprintf("CDN detected: %s", result.CDN.Provider),
			Detail:   "Using a CDN improves global performance and reliability",
		})
	}

	// Cloud Provider
	if result.CloudProvider.Provider != "" {
		detail := fmt.Sprintf("Hosted on %s", result.CloudProvider.Provider)
		if result.CloudProvider.Region != "" {
			detail += fmt.Sprintf(" in %s region", result.CloudProvider.Region)
		}
		findings = append(findings, types.Finding{
			Severity: "info",
			Category: "Infrastructure",
			Message:  fmt.Sprintf("Cloud infrastructure: %s", result.CloudProvider.Provider),
			Detail:   detail,
		})
	}

	// Service Mesh
	if result.ServiceMesh.Detected {
		findings = append(findings, types.Finding{
			Severity: "info",
			Category: "Infrastructure",
			Message:  fmt.Sprintf("Service mesh detected: %s", result.ServiceMesh.Type),
			Detail:   "Modern microservices architecture with service mesh capabilities",
		})
	}

	// Load Balancer
	if result.LoadBalancer.Detected {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Infrastructure",
			Message:  fmt.Sprintf("Load balancer detected: %s", result.LoadBalancer.Type),
			Detail:   "Using load balancing for high availability and scalability",
		})
	}

	// Container Platform
	if result.Container.Detected {
		findings = append(findings, types.Finding{
			Severity: "info",
			Category: "Infrastructure",
			Message:  fmt.Sprintf("Container platform: %s", result.Container.Platform),
			Detail:   "Containerized deployment detected",
		})
	}

	return findings
}

func analyzeDNS(dns types.DNSInfo) []types.Finding {
	var findings []types.Finding

	// IPv6 Support
	if len(dns.AAAA) > 0 {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Configuration",
			Message:  "IPv6 support enabled",
			Detail:   fmt.Sprintf("Site accessible via %d IPv6 address(es)", len(dns.AAAA)),
		})
	} else if len(dns.A) > 0 {
		findings = append(findings, types.Finding{
			Severity: "info",
			Category: "Configuration",
			Message:  "No IPv6 support detected",
			Detail:   "Consider enabling IPv6 for future-proofing",
		})
	}

	// Multiple A records (load balancing/redundancy)
	if len(dns.A) > 2 {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Configuration",
			Message:  fmt.Sprintf("DNS load balancing detected (%d A records)", len(dns.A)),
			Detail:   "Multiple A records suggest DNS-based load balancing or redundancy",
		})
	}

	// CAA Records
	if len(dns.CAA) > 0 {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Security",
			Message:  "CAA records configured",
			Detail:   "Certificate Authority Authorization helps prevent unauthorized certificate issuance",
		})
	}

	// SPF Record
	hasSPF := false
	for _, txt := range dns.TXT {
		if strings.HasPrefix(txt, "v=spf1") {
			hasSPF = true
			break
		}
	}
	if hasSPF {
		findings = append(findings, types.Finding{
			Severity: "positive",
			Category: "Security",
			Message:  "SPF record configured",
			Detail:   "Sender Policy Framework helps prevent email spoofing",
		})
	}

	return findings
}

func analyzePorts(ports []types.PortInfo) []types.Finding {
	var findings []types.Finding

	openPorts := []string{}
	for _, port := range ports {
		if port.Status == "Open" {
			openPorts = append(openPorts, strconv.Itoa(port.Port))
		}
	}

	if len(openPorts) > 0 {
		findings = append(findings, types.Finding{
			Severity: "info",
			Category: "Security",
			Message:  fmt.Sprintf("Open ports detected: %s", strings.Join(openPorts, ", ")),
			Detail:   "Ensure all open ports are necessary and properly secured",
		})
	}

	// Check for unusual ports
	for _, port := range ports {
		if port.Status == "Open" && (port.Port == 8080 || port.Port == 8443 || port.Port == 3000) {
			findings = append(findings, types.Finding{
				Severity: "warning",
				Category: "Security",
				Message:  fmt.Sprintf("Development port open: %d", port.Port),
				Detail:   "Port typically used for development may be exposed to production",
			})
		}
	}

	return findings
}
