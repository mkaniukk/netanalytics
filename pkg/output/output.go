package output

import (
	"fmt"
	"strings"

	"github.com/mkaniukk/netanalytics/pkg/types"
)

func printFindings(findings []types.Finding) {
	if len(findings) == 0 {
		return
	}

	fmt.Println("\n🔍 Key Findings:")

	// Group findings by severity
	critical := []types.Finding{}
	warnings := []types.Finding{}
	positives := []types.Finding{}
	info := []types.Finding{}

	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critical = append(critical, f)
		case "warning":
			warnings = append(warnings, f)
		case "positive":
			positives = append(positives, f)
		case "info":
			info = append(info, f)
		}
	}

	// Print critical findings first
	for _, f := range critical {
		fmt.Printf("\n  ❌ [CRITICAL] %s\n", f.Message)
		if f.Detail != "" {
			fmt.Printf("     → %s\n", f.Detail)
		}
	}

	// Print warnings
	for _, f := range warnings {
		fmt.Printf("\n  ⚠️  [WARNING] %s\n", f.Message)
		if f.Detail != "" {
			fmt.Printf("     → %s\n", f.Detail)
		}
	}

	// Print positive findings
	for _, f := range positives {
		fmt.Printf("\n  ✅ [POSITIVE] %s\n", f.Message)
		if f.Detail != "" {
			fmt.Printf("     → %s\n", f.Detail)
		}
	}

	// Print info
	for _, f := range info {
		fmt.Printf("\n  ℹ️  [INFO] %s\n", f.Message)
		if f.Detail != "" {
			fmt.Printf("     → %s\n", f.Detail)
		}
	}

	fmt.Println()
}

func PrintReport(r types.AnalysisResult, verbose bool) {
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Printf("Host: %s\n", r.Host)
	fmt.Printf("Time: %s\n", r.Timestamp)
	if len(r.IP) > 0 {
		fmt.Printf("Resolved IP(s): %v\n", r.IP)
	}
	fmt.Println(strings.Repeat("=", 50))

	// Print key findings first
	if len(r.Findings) > 0 {
		printFindings(r.Findings)
	}
	fmt.Println()

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
	if r.DNS.Duration != "" {
		fmt.Printf("  Lookup: %s\n", r.DNS.Duration)
	}
	fmt.Println()

	if r.TLS.Version != "" {
		fmt.Println("TLS Certificate:")
		fmt.Printf("  Protocol:  %s\n", r.TLS.Version)
		fmt.Printf("  Cipher:    %s\n", r.TLS.CipherSuite)
		if r.TLS.CipherStrength != "" {
			fmt.Printf("  Strength:  %s\n", r.TLS.CipherStrength)
		}
		if r.TLS.KeyExchange != "" {
			fmt.Printf("  Key Exch:  %s\n", r.TLS.KeyExchange)
		}
		fmt.Printf("  Subject:   %s\n", r.TLS.Subject)
		fmt.Printf("  Issuer:    %s\n", r.TLS.Issuer)
		fmt.Printf("  Key Type:  %s\n", r.TLS.KeyType)
		if r.TLS.KeySize > 0 {
			fmt.Printf("  Key Size:  %d bits\n", r.TLS.KeySize)
		}
		if r.TLS.PublicKeyAlgo != "" {
			fmt.Printf("  Pub Key:   %s\n", r.TLS.PublicKeyAlgo)
		}
		if r.TLS.SignatureAlgo != "" {
			fmt.Printf("  Signature: %s\n", r.TLS.SignatureAlgo)
		}
		if r.TLS.NotBefore != "" {
			fmt.Printf("  Valid From:%s\n", r.TLS.NotBefore)
		}
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

	if r.Network.IPVersion != "" || r.Network.ReverseDNS != "" || len(r.Network.Hops) > 0 {
		fmt.Println("Network Information:")
		if r.Network.IPVersion != "" {
			fmt.Printf("  IP Version:   %s\n", r.Network.IPVersion)
		}
		if r.Network.ReverseDNS != "" {
			fmt.Printf("  Reverse DNS:  %s\n", r.Network.ReverseDNS)
		}
		if len(r.Network.Hops) > 0 {
			fmt.Printf("\n  Network Hops (%d total):\n", len(r.Network.Hops))
			for _, hop := range r.Network.Hops {
				if hop.Hostname != "" {
					fmt.Printf("    %2d. %-15s %-40s %s\n", hop.Hop, hop.IP, hop.Hostname, hop.RTT)
				} else {
					fmt.Printf("    %2d. %-15s %s\n", hop.Hop, hop.IP, hop.RTT)
				}
			}
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
		if r.HTTP.Duration != "" {
			fmt.Printf("  Latency:  %s\n", r.HTTP.Duration)
		}
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

		// Content Information
		if r.Content.RobotsTxt || r.Content.SitemapXml || r.Content.SecurityTxt {
			fmt.Println("\nContent Information:")
			if r.Content.RobotsTxt {
				fmt.Printf("  robots.txt:    Found (%d bytes)\n", r.Content.RobotsSize)
			} else {
				fmt.Printf("  robots.txt:    Not Found\n")
			}
			if r.Content.SitemapXml {
				fmt.Printf("  sitemap.xml:   Found (%d bytes)\n", r.Content.SitemapSize)
			} else {
				fmt.Printf("  sitemap.xml:   Not Found\n")
			}
			if r.Content.SecurityTxt {
				fmt.Printf("  security.txt:  Found (%d bytes)\n", r.Content.SecuritySize)
			} else {
				fmt.Printf("  security.txt:  Not Found\n")
			}
		}

		if len(r.Content.ExposedFiles) > 0 {
			fmt.Println("\nExposed Files:")
			for _, file := range r.Content.ExposedFiles {
				fmt.Printf("  ⚠️  %s\n", file)
			}
		}

		// Email Security
		if r.EmailSecurity.SPF || r.EmailSecurity.DMARC {
			fmt.Println("\nEmail Security:")
			if r.EmailSecurity.SPF {
				fmt.Printf("  SPF Record:    %s\n", r.EmailSecurity.SPFRecord)
			} else {
				fmt.Printf("  SPF Record:    Not Found\n")
			}
			if r.EmailSecurity.DMARC {
				fmt.Printf("  DMARC Record:  %s\n", r.EmailSecurity.DMARCRecord)
				if r.EmailSecurity.DMARCPolicy != "" {
					fmt.Printf("  DMARC Policy:  %s\n", r.EmailSecurity.DMARCPolicy)
				}
			} else {
				fmt.Printf("  DMARC Record:  Not Found\n")
			}
		}

		if len(r.Components) > 0 {
			fmt.Println("\nSoftware Components:")
			for _, comp := range r.Components {
				label := strings.TrimSpace(comp.Name + " " + comp.Version)
				if label == "" {
					label = comp.Name
				}
				if comp.Source != "" {
					fmt.Printf("  %s (%s)\n", label, comp.Source)
				} else {
					fmt.Printf("  %s\n", label)
				}
			}
		}

		if len(r.Vulnerabilities) > 0 {
			fmt.Println("\nCVE Findings:")
			for _, result := range r.Vulnerabilities {
				label := strings.TrimSpace(result.Component.Name + " " + result.Component.Version)
				if label == "" {
					label = "Unknown Component"
				}
				if result.Component.Source != "" {
					fmt.Printf("  %s [%s]:\n", label, result.Component.Source)
				} else {
					fmt.Printf("  %s:\n", label)
				}
				for _, entry := range result.Matches {
					score := ""
					if entry.CVSS > 0 {
						score = fmt.Sprintf(" (CVSS %.1f %s)", entry.CVSS, strings.ToUpper(entry.Severity))
					} else if entry.Severity != "" {
						score = fmt.Sprintf(" (%s)", strings.ToUpper(entry.Severity))
					}
					fmt.Printf("    - %s%s\n", entry.ID, score)
					if entry.Description != "" {
						fmt.Printf("      %s\n", entry.Description)
					}
					if entry.URL != "" {
						fmt.Printf("      %s\n", entry.URL)
					}
				}
			}
		}

		if r.Performance.DNSLookup != "" || r.Performance.TCPConnect != "" || r.Performance.TLSHandshake != "" || r.Performance.FirstByte != "" || r.Performance.TotalTime != "" {
			fmt.Println("\nPerformance Metrics:")
			if r.Performance.DNSLookup != "" {
				fmt.Printf("  DNS Lookup:     %s\n", r.Performance.DNSLookup)
			}
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

		// Show security headers - all if verbose, only set ones otherwise
		if verbose {
			fmt.Println("\nSecurity Headers:")
			for header, value := range r.HTTP.SecurityHeaders {
				if value == "Not Set" {
					fmt.Printf("  %-30s ⚠️  %s\n", header+":", value)
				} else {
					fmt.Printf("  %-30s ✓  %s\n", header+":", value)
				}
			}
		} else {
			hasSetHeaders := false
			for _, value := range r.HTTP.SecurityHeaders {
				if value != "Not Set" {
					hasSetHeaders = true
					break
				}
			}

			if hasSetHeaders {
				fmt.Println("\nSecurity Headers:")
				for header, value := range r.HTTP.SecurityHeaders {
					if value != "Not Set" {
						fmt.Printf("  %-30s ✓  %s\n", header+":", value)
					}
				}
			}
		}
	}

	// Print WHOIS information
	printWHOIS(r.WHOIS)

	// Print Subdomain information
	printSubdomains(r.Subdomains, verbose)

	// Print DNSSEC information
	printDNSSEC(r.DNSSEC)

	// Print WAF information
	printWAF(r.WAF)

	// Print HTTP Methods
	printHTTPMethods(r.HTTPMethods, verbose)

	// Print CORS information
	printCORS(r.CORS)

	// Print Latency information
	printLatency(r.Latency, verbose)

	// Print Security.txt information
	printSecurityTxt(r.SecurityTxt)

	// Print IPv6 information
	printIPv6(r.IPv6)

	// Print Redirect information
	printRedirects(r.Redirects, verbose)

	// Print Banner information
	printBanners(r.Banners)
}

func printWHOIS(w types.WHOISInfo) {
	if w.Registrar == "" {
		return
	}
	fmt.Println("\nWHOIS Information:")
	fmt.Printf("  Registrar:     %s\n", w.Registrar)
	if w.Registrant != "" {
		fmt.Printf("  Registrant:    %s\n", w.Registrant)
	}
	if w.CreationDate != "" {
		fmt.Printf("  Created:       %s\n", w.CreationDate)
	}
	if w.DomainAge != "" {
		fmt.Printf("  Domain Age:    %s\n", w.DomainAge)
	}
	if w.UpdatedDate != "" {
		fmt.Printf("  Last Updated:  %s\n", w.UpdatedDate)
	}
	if w.ExpiryDate != "" {
		fmt.Printf("  Expires:       %s\n", w.ExpiryDate)
	}
	if len(w.NameServers) > 0 {
		fmt.Printf("  Name Servers:  %v\n", w.NameServers)
	}
	if len(w.DomainStatus) > 0 {
		fmt.Printf("  Status:        %v\n", w.DomainStatus)
	}
}

func printSubdomains(s types.SubdomainInfo, verbose bool) {
	if s.Count == 0 {
		return
	}
	fmt.Println("\nSubdomain Enumeration:")
	fmt.Printf("  Total Found:   %d subdomains\n", s.Count)
	fmt.Printf("  Sources:       %v\n", s.Sources)

	if len(s.Resolved) > 0 {
		fmt.Println("  Active Subdomains:")
		displayCount := len(s.Resolved)
		if !verbose && displayCount > 10 {
			displayCount = 10
		}
		for i, res := range s.Resolved {
			if i >= displayCount {
				fmt.Printf("    ... and %d more (use --verbose to see all)\n", len(s.Resolved)-displayCount)
				break
			}
			if res.Active {
				if res.CNAME != "" {
					fmt.Printf("    %s -> %s (CNAME: %s)\n", res.Subdomain, strings.Join(res.IPs, ", "), res.CNAME)
				} else {
					fmt.Printf("    %s -> %s\n", res.Subdomain, strings.Join(res.IPs, ", "))
				}
			}
		}
	}
}

func printDNSSEC(d types.DNSSECInfo) {
	if d.Domain == "" {
		return
	}
	fmt.Println("\nDNSSEC:")
	if d.Enabled {
		status := "✓ Enabled"
		if d.Valid {
			status += " (Valid)"
		} else {
			status += " (Incomplete chain)"
		}
		fmt.Printf("  Status:       %s\n", status)
		if d.Algorithm != "" {
			fmt.Printf("  Algorithm:    %s\n", d.Algorithm)
		}
		if d.KeyType != "" {
			fmt.Printf("  Key Type:     %s\n", d.KeyType)
		}
	} else {
		fmt.Printf("  Status:       Not enabled\n")
	}
}

func printWAF(w types.WAFInfo) {
	if !w.Detected {
		return
	}
	fmt.Println("\nWAF Detection:")
	fmt.Printf("  Detected:      ✓ %s\n", w.Name)
	if len(w.Evidence) > 0 {
		fmt.Printf("  Evidence:      %v\n", w.Evidence)
	}
}

func printHTTPMethods(m types.HTTPMethodsInfo, verbose bool) {
	if len(m.Methods) == 0 {
		return
	}
	fmt.Println("\nHTTP Methods:")
	fmt.Printf("  Allowed:       %v\n", m.Allowed)
	if len(m.DangerousMethods) > 0 {
		fmt.Printf("  ⚠️  Dangerous:  %v\n", m.DangerousMethods)
	}
	if verbose {
		fmt.Println("  Details:")
		for _, method := range m.Methods {
			status := "✗"
			if method.Allowed {
				status = "✓"
			}
			fmt.Printf("    %s %s (%d)\n", status, method.Method, method.StatusCode)
		}
	}
}

func printCORS(c types.CORSInfo) {
	if !c.Enabled {
		return
	}
	fmt.Println("\nCORS Configuration:")
	fmt.Printf("  Allow-Origin:       %s\n", c.AllowOrigin)
	fmt.Printf("  Allow-Credentials:  %t\n", c.AllowCredentials)
	if c.AllowMethods != "" {
		fmt.Printf("  Allow-Methods:      %s\n", c.AllowMethods)
	}
	if c.Misconfigured {
		fmt.Println("  ⚠️  Issues:")
		for _, issue := range c.Issues {
			fmt.Printf("    - %s\n", issue)
		}
	}
}

func printLatency(l types.LatencyInfo, verbose bool) {
	if l.Average == "" {
		return
	}
	fmt.Println("\nLatency Analysis:")
	fmt.Printf("  Samples:       %d\n", l.Samples)
	fmt.Printf("  Average:       %s\n", l.Average)
	fmt.Printf("  Min:           %s\n", l.Min)
	fmt.Printf("  Max:           %s\n", l.Max)
	if l.StdDev != "" {
		fmt.Printf("  Std Dev:       %s\n", l.StdDev)
	}
	if l.Jitter != "" {
		fmt.Printf("  Jitter:        %s\n", l.Jitter)
	}
	if verbose && len(l.Measurements) > 0 {
		fmt.Printf("  Measurements:  %v\n", l.Measurements)
	}
}

func printSecurityTxt(s types.SecurityTxtInfo) {
	if !s.Found {
		return
	}
	fmt.Println("\nsecurity.txt:")
	fmt.Printf("  Location:      %s\n", s.Location)
	if len(s.Contact) > 0 {
		fmt.Printf("  Contact:       %v\n", s.Contact)
	}
	if s.Expires != "" {
		expiredMark := ""
		if s.Expired {
			expiredMark = " ⚠️ EXPIRED"
		}
		fmt.Printf("  Expires:       %s%s\n", s.Expires, expiredMark)
	}
	if s.Encryption != "" {
		fmt.Printf("  Encryption:    %s\n", s.Encryption)
	}
	if s.Acknowledgments != "" {
		fmt.Printf("  Acknowledgments: %s\n", s.Acknowledgments)
	}
	if s.Policy != "" {
		fmt.Printf("  Policy:        %s\n", s.Policy)
	}
	if s.Hiring != "" {
		fmt.Printf("  Hiring:        %s\n", s.Hiring)
	}
	if len(s.Issues) > 0 {
		fmt.Println("  ⚠️  Issues:")
		for _, issue := range s.Issues {
			fmt.Printf("    - %s\n", issue)
		}
	}
}

func printIPv6(i types.IPv6Info) {
	if i.Host == "" {
		return
	}
	fmt.Println("\nIPv6 Support:")
	if i.HasAAAA {
		fmt.Printf("  AAAA Records:  ✓ %v\n", i.Addresses)
		if i.Reachable {
			fmt.Printf("  Reachable:     ✓ Yes\n")
		} else {
			fmt.Printf("  Reachable:     ✗ No (connection failed)\n")
		}
	} else {
		fmt.Printf("  AAAA Records:  ✗ None\n")
	}
}

func printRedirects(r types.RedirectInfo, verbose bool) {
	if len(r.HTTPChain) == 0 && len(r.HTTPSChain) == 0 {
		return
	}
	fmt.Println("\nRedirect Analysis:")
	if r.HTTPSUpgrade {
		fmt.Printf("  HTTPS Upgrade: ✓ HTTP redirects to HTTPS\n")
	}
	if verbose {
		if len(r.HTTPChain) > 0 {
			fmt.Println("  HTTP Chain:")
			for i, hop := range r.HTTPChain {
				fmt.Printf("    %d. [%d] %s\n", i+1, hop.StatusCode, hop.URL)
			}
		}
		if len(r.HTTPSChain) > 0 {
			fmt.Println("  HTTPS Chain:")
			for i, hop := range r.HTTPSChain {
				fmt.Printf("    %d. [%d] %s\n", i+1, hop.StatusCode, hop.URL)
			}
		}
	}
}

func printBanners(b types.BannerInfo) {
	if b.Server == "" && b.SSH == "" && b.FTP == "" && b.SMTP == "" {
		return
	}
	fmt.Println("\nService Banners:")
	if b.Server != "" {
		fmt.Printf("  HTTP Server:   %s\n", b.Server)
	}
	if b.XPoweredBy != "" {
		fmt.Printf("  X-Powered-By:  %s\n", b.XPoweredBy)
	}
	if b.SSH != "" {
		fmt.Printf("  SSH:           %s\n", b.SSH)
	}
	if b.FTP != "" {
		fmt.Printf("  FTP:           %s\n", b.FTP)
	}
	if b.SMTP != "" {
		fmt.Printf("  SMTP:          %s\n", b.SMTP)
	}
	if b.VersionDisclosed {
		fmt.Printf("  ⚠️  Version disclosure detected in %d service(s)\n", len(b.Versions))
	}
}
