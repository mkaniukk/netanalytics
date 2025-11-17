package output

import (
	"fmt"
	"strings"

	"netanalyze/pkg/types"
)

func PrintReport(r types.AnalysisResult) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 50))
	fmt.Printf("Host: %s\n", r.Host)
	fmt.Printf("Time: %s\n", r.Timestamp)
	fmt.Printf("%s\n\n", strings.Repeat("=", 50))

	fmt.Println("DNS Records:")
	if len(r.DNS.A) > 0 {
		fmt.Printf("  A:      %v\n", r.DNS.A)
	}
	if len(r.DNS.AAAA) > 0 {
		fmt.Printf("  AAAA:   %v\n", r.DNS.AAAA)
	}
	if len(r.DNS.CNAME) > 0 {
		fmt.Printf("  CNAME:  %v\n", r.DNS.CNAME)
	}
	if len(r.DNS.MX) > 0 {
		fmt.Printf("  MX:     %v\n", r.DNS.MX)
	}
	if len(r.DNS.NS) > 0 {
		fmt.Printf("  NS:     %v\n", r.DNS.NS)
	}
	if len(r.DNS.TXT) > 0 {
		fmt.Printf("  TXT:    %v\n", r.DNS.TXT)
	}
	if r.DNS.SOA != "" {
		fmt.Printf("  SOA:    %s\n", r.DNS.SOA)
	}
	if len(r.DNS.Reverse) > 0 {
		fmt.Printf("  PTR:    %v\n", r.DNS.Reverse)
	}
	if len(r.DNS.CAA) > 0 {
		fmt.Printf("  CAA:    %v\n", r.DNS.CAA)
	}
	fmt.Printf("  Lookup: %s\n\n", r.DNS.Duration)

	if r.TLS.Version != "" {
		fmt.Println("TLS Certificate:")
		fmt.Printf("  Protocol:  %s\n", r.TLS.Version)
		fmt.Printf("  Cipher:    %s\n", r.TLS.CipherSuite)
		fmt.Printf("  Subject:   %s\n", r.TLS.Subject)
		fmt.Printf("  Issuer:    %s\n", r.TLS.Issuer)
		fmt.Printf("  Key:       %s\n", r.TLS.KeyType)
		fmt.Printf("  Expires:   %s\n", r.TLS.Expiry)
		if len(r.TLS.SAN) > 0 {
			fmt.Printf("  SAN:       %v\n", r.TLS.SAN)
		}
		if r.TLS.SerialNumber != "" {
			fmt.Printf("  Serial:    %s\n", r.TLS.SerialNumber)
		}
		if r.TLS.ChainLength > 0 {
			fmt.Printf("  Chain:     %d certificate(s)\n", r.TLS.ChainLength)
		}
		if r.TLS.OCSPStapling {
			fmt.Printf("  OCSP:      Enabled\n")
		}

		if r.SSLGrade.Grade != "" {
			fmt.Printf("\n  SSL Grade: %s (Score: %d/100)\n", r.SSLGrade.Grade, r.SSLGrade.Score)
			if r.SSLGrade.CertExpiresDays > 0 {
				fmt.Printf("  Expires in: %d days\n", r.SSLGrade.CertExpiresDays)
			}
			if len(r.SSLGrade.Strengths) > 0 {
				fmt.Printf("  Strengths: %v\n", r.SSLGrade.Strengths)
			}
			if len(r.SSLGrade.Issues) > 0 {
				fmt.Printf("  Issues: %v\n", r.SSLGrade.Issues)
			}
		}
		fmt.Println()
	}

	if r.CDN.Detected {
		fmt.Println("CDN Detection:")
		fmt.Printf("  Provider:  %s\n", r.CDN.Provider)
		if len(r.CDN.Headers) > 0 {
			fmt.Printf("  Evidence:  %v\n", r.CDN.Headers)
		}
		fmt.Println()
	}

	if r.CloudProvider.Provider != "" {
		fmt.Println("Cloud Provider:")
		fmt.Printf("  Provider:  %s\n", r.CloudProvider.Provider)
		if r.CloudProvider.Region != "" {
			fmt.Printf("  Region:    %s\n", r.CloudProvider.Region)
		}
		if len(r.CloudProvider.Service) > 0 {
			fmt.Printf("  Services:  %v\n", r.CloudProvider.Service)
		}
		fmt.Println()
	}

	if r.ServiceMesh.Detected {
		fmt.Println("Service Mesh:")
		fmt.Printf("  Type:      %s\n", r.ServiceMesh.Type)
		if r.ServiceMesh.Version != "" {
			fmt.Printf("  Version:   %s\n", r.ServiceMesh.Version)
		}
		if r.ServiceMesh.TraceID != "" {
			fmt.Printf("  Trace ID:  %s\n", r.ServiceMesh.TraceID)
		}
		if len(r.ServiceMesh.Headers) > 0 {
			fmt.Printf("  Headers:   %v\n", r.ServiceMesh.Headers)
		}
		fmt.Println()
	}

	if r.LoadBalancer.Detected {
		fmt.Println("Load Balancer:")
		fmt.Printf("  Type:      %s\n", r.LoadBalancer.Type)
		if r.LoadBalancer.Backend != "" {
			fmt.Printf("  Backend:   %s\n", r.LoadBalancer.Backend)
		}
		if len(r.LoadBalancer.Headers) > 0 {
			fmt.Printf("  Headers:   %v\n", r.LoadBalancer.Headers)
		}
		fmt.Println()
	}

	if r.Container.Detected {
		fmt.Println("Container Environment:")
		if r.Container.Orchestrator != "" {
			fmt.Printf("  Orchestrator: %s\n", r.Container.Orchestrator)
		}
		if r.Container.Platform != "" {
			fmt.Printf("  Platform:     %s\n", r.Container.Platform)
		}
		if r.Container.Ingress != "" {
			fmt.Printf("  Ingress:      %s\n", r.Container.Ingress)
		}
		if r.Container.Registry != "" {
			fmt.Printf("  Registry:     %s\n", r.Container.Registry)
		}
		if len(r.Container.Headers) > 0 {
			fmt.Printf("  Headers:      %v\n", r.Container.Headers)
		}
		fmt.Println()
	}

	if len(r.Geo) > 0 {
		fmt.Println("IP Information:")
		geo := r.Geo[0]
		fmt.Printf("  IP Address:   %s\n", geo.IP)
		if geo.Country != "" {
			fmt.Printf("  Country:      %s\n", geo.Country)
		}
		if geo.City != "" {
			fmt.Printf("  City:         %s\n", geo.City)
		}
		if geo.ISP != "" {
			fmt.Printf("  ISP Provider: %s\n", geo.ISP)
		}
		if geo.Organization != "" {
			fmt.Printf("  Organization: %s\n", geo.Organization)
		}
		if geo.ASN != "" {
			fmt.Printf("  ASN:          %s\n", geo.ASN)
		}
		if geo.Hosting != "" {
			fmt.Printf("  Hosting:      %s\n", geo.Hosting)
		}
		if geo.Proxy {
			fmt.Printf("  Proxy:        Yes\n")
		}
		if geo.Mobile {
			fmt.Printf("  Mobile:       Yes\n")
		}
		fmt.Println()
	}

	if r.Network.IPVersion != "" || r.Network.ReverseDNS != "" {
		fmt.Println("Network Information:")
		if r.Network.IPVersion != "" {
			fmt.Printf("  IP Version:   %s\n", r.Network.IPVersion)
		}
		if r.Network.ReverseDNS != "" {
			fmt.Printf("  Reverse DNS:  %s\n", r.Network.ReverseDNS)
		}
		fmt.Println()
	}

	if len(r.Ports) > 0 {
		fmt.Println("Open Ports:")
		for _, port := range r.Ports {
			fmt.Printf("  %-6d %-10s %s\n", port.Port, port.Status, port.Service)
		}
		fmt.Println()
	}

	if r.HTTP.Status > 0 {
		fmt.Println("HTTP Response:")
		fmt.Printf("  Status:   %d\n", r.HTTP.Status)
		if r.HTTP.TechStack.HTTPVersion != "" {
			fmt.Printf("  Protocol: %s\n", r.HTTP.TechStack.HTTPVersion)
		}
		if r.HTTP.Server != "" {
			fmt.Printf("  Server:   %s\n", r.HTTP.Server)
		}
		if r.HTTP.OS != "" && r.HTTP.OS != "Unknown" {
			fmt.Printf("  OS:       %s\n", r.HTTP.OS)
		}
		if r.HTTP.PoweredBy != "" {
			fmt.Printf("  Powered:  %s\n", r.HTTP.PoweredBy)
		}
		if len(r.HTTP.Technology) > 0 {
			fmt.Printf("  Tech:     %v\n", r.HTTP.Technology)
		}
		if r.HTTP.ContentType != "" {
			fmt.Printf("  Type:     %s\n", r.HTTP.ContentType)
		}
		if r.HTTP.Encoding != "" {
			fmt.Printf("  Encoding: %s\n", r.HTTP.Encoding)
		}
		if r.HTTP.ContentLength > 0 {
			fmt.Printf("  Size:     %d bytes\n", r.HTTP.ContentLength)
		}
		fmt.Printf("  Latency:  %s\n", r.HTTP.Duration)
		if len(r.HTTP.RedirectChain) > 0 {
			fmt.Printf("  Redirects: %v\n", r.HTTP.RedirectChain)
		}
		if len(r.HTTP.Cookies) > 0 {
			fmt.Printf("  Cookies:  %v\n", r.HTTP.Cookies)
		}

		if r.HTTP.TechStack.CMS != "" || len(r.HTTP.TechStack.Language) > 0 || len(r.HTTP.TechStack.JavaScript) > 0 {
			fmt.Println("\n  Technology Stack:")
			if r.HTTP.TechStack.CMS != "" {
				fmt.Printf("    CMS:        %s\n", r.HTTP.TechStack.CMS)
			}
			if len(r.HTTP.TechStack.Language) > 0 {
				fmt.Printf("    Language:   %v\n", r.HTTP.TechStack.Language)
			}
			if len(r.HTTP.TechStack.Framework) > 0 {
				fmt.Printf("    Framework:  %v\n", r.HTTP.TechStack.Framework)
			}
			if len(r.HTTP.TechStack.JavaScript) > 0 {
				fmt.Printf("    JavaScript: %v\n", r.HTTP.TechStack.JavaScript)
			}
			if len(r.HTTP.TechStack.Analytics) > 0 {
				fmt.Printf("    Analytics:  %v\n", r.HTTP.TechStack.Analytics)
			}
		}

		if r.Performance.DNSLookup != "" {
			fmt.Println("\nPerformance Metrics:")
			fmt.Printf("  DNS Lookup:     %s\n", r.Performance.DNSLookup)
			if r.Performance.TCPConnect != "" {
				fmt.Printf("  TCP Connect:    %s\n", r.Performance.TCPConnect)
			}
			if r.Performance.TLSHandshake != "" {
				fmt.Printf("  TLS Handshake:  %s\n", r.Performance.TLSHandshake)
			}
			if r.Performance.FirstByte != "" {
				fmt.Printf("  First Byte:     %s\n", r.Performance.FirstByte)
			}
			if r.Performance.TotalTime != "" {
				fmt.Printf("  Total Time:     %s\n", r.Performance.TotalTime)
			}
		}

		fmt.Println("\nSecurity Headers:")
		for header, value := range r.HTTP.SecurityHeaders {
			if value == "Not Set" {
				fmt.Printf("  %-30s ⚠️  %s\n", header+":", value)
			} else {
				fmt.Printf("  %-30s ✓  %s\n", header+":", value)
			}
		}
	}
}
