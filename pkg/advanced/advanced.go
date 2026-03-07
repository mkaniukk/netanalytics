package advanced

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/mkaniukk/netanalytics/pkg/types"
)

// CheckDNSSEC validates DNSSEC configuration for a domain
func CheckDNSSEC(domain string) types.DNSSECInfo {
	info := types.DNSSECInfo{
		Domain: domain,
	}

	c := new(dns.Client)
	m := new(dns.Msg)

	// Check for DNSKEY records
	m.SetQuestion(dns.Fqdn(domain), dns.TypeDNSKEY)
	m.SetEdns0(4096, true) // Enable DNSSEC OK flag

	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return info
	}

	for _, ans := range r.Answer {
		if dnskey, ok := ans.(*dns.DNSKEY); ok {
			info.Enabled = true
			info.Algorithm = dns.AlgorithmToString[dnskey.Algorithm]
			if dnskey.Flags&dns.ZONE != 0 {
				info.KeyType = "ZSK"
			}
			if dnskey.Flags&dns.SEP != 0 {
				info.KeyType = "KSK"
			}
			info.Keys = append(info.Keys, fmt.Sprintf("Algorithm: %s, Flags: %d", info.Algorithm, dnskey.Flags))
		}
	}

	// Check for DS records at parent
	m2 := new(dns.Msg)
	m2.SetQuestion(dns.Fqdn(domain), dns.TypeDS)
	m2.SetEdns0(4096, true)

	r2, _, err := c.Exchange(m2, "8.8.8.8:53")
	if err == nil {
		for _, ans := range r2.Answer {
			if ds, ok := ans.(*dns.DS); ok {
				info.DSRecords = append(info.DSRecords, fmt.Sprintf("KeyTag: %d, Algorithm: %s, DigestType: %d",
					ds.KeyTag, dns.AlgorithmToString[ds.Algorithm], ds.DigestType))
			}
		}
	}

	// Validate chain
	if info.Enabled && len(info.DSRecords) > 0 {
		info.Valid = true
	}

	return info
}

// DetectWAF attempts to detect Web Application Firewalls
func DetectWAF(host string) types.WAFInfo {
	info := types.WAFInfo{}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseURL := "https://" + host

	// First, make a normal request to get baseline
	normalResp, err := client.Get(baseURL)
	if err != nil {
		return info
	}
	normalResp.Body.Close()

	// Check headers for WAF signatures
	info = checkWAFHeaders(normalResp.Header, info)

	// If not detected yet, try malicious payloads
	if !info.Detected {
		// Test with SQL injection payload
		testURLs := []string{
			baseURL + "/?id=1' OR '1'='1",
			baseURL + "/?q=<script>alert(1)</script>",
			baseURL + "/?file=../../../etc/passwd",
			baseURL + "/?cmd=;cat /etc/passwd",
		}

		for _, testURL := range testURLs {
			req, _ := http.NewRequest("GET", testURL, nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityScanner/1.0)")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			// Check for WAF response
			if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 ||
				resp.StatusCode == 503 {
				info = checkWAFHeaders(resp.Header, info)
				if !info.Detected {
					// Read body for WAF detection
					body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
					info = checkWAFBody(string(body), info)
				}
			}

			if info.Detected {
				break
			}
		}
	}

	return info
}

func checkWAFHeaders(headers http.Header, info types.WAFInfo) types.WAFInfo {
	wafSignatures := map[string]map[string]string{
		"Cloudflare": {
			"Server":          "cloudflare",
			"CF-RAY":          "",
			"CF-Cache-Status": "",
		},
		"AWS WAF": {
			"X-AMZ-ID-2":             "",
			"X-AMZ-REQUEST-ID":       "",
			"X-AMZN-WAFBLOCK":        "",
			"X-AMZN-REQUESTID":       "",
			"X-AMZN-ERRORTYPE":       "",
			"X-AMZ-CF-ID":            "",
			"X-AMZ-APIGW-ID":         "",
			"X-AMZN-TRACE-ID":        "",
			"X-AMZN-WAFMANAGEDBLOCK": "",
		},
		"Akamai": {
			"X-Akamai-Transformed":  "",
			"Akamai-Origin-Hop":     "",
			"X-Akamai-Session-Info": "",
			"X-Akamai-Request-ID":   "",
		},
		"Imperva Incapsula": {
			"X-CDN":     "Incapsula",
			"X-Iinfo":   "",
			"Incap_ses": "",
		},
		"F5 BIG-IP ASM": {
			"X-WA-Info":  "",
			"X-Cnection": "",
		},
		"ModSecurity": {
			"Server": "mod_security",
		},
		"Sucuri": {
			"X-Sucuri-ID":    "",
			"X-Sucuri-Cache": "",
			"Server":         "Sucuri",
		},
		"StackPath": {
			"X-SP-URL":  "",
			"X-SP-WL":   "",
			"X-SP-EDGE": "",
		},
		"Fastly": {
			"X-Fastly-Request-ID": "",
			"Fastly-Debug-Digest": "",
		},
		"Barracuda": {
			"BARRA_COUNTER_SESSION": "",
		},
		"DDoS-Guard": {
			"Server": "ddos-guard",
		},
		"Wallarm": {
			"X-Wallarm-Wlcr": "",
		},
	}

	for wafName, signatures := range wafSignatures {
		for header, expectedValue := range signatures {
			if value := headers.Get(header); value != "" {
				if expectedValue == "" || strings.Contains(strings.ToLower(value), strings.ToLower(expectedValue)) {
					info.Detected = true
					info.Name = wafName
					info.Evidence = append(info.Evidence, fmt.Sprintf("Header %s: %s", header, value))
					return info
				}
			}
		}
	}

	return info
}

func checkWAFBody(body string, info types.WAFInfo) types.WAFInfo {
	bodyLower := strings.ToLower(body)

	wafBodySignatures := map[string][]string{
		"Cloudflare": {
			"attention required! | cloudflare",
			"cloudflare ray id",
			"why have i been blocked",
		},
		"AWS WAF": {
			"request blocked",
			"aws waf",
		},
		"Akamai": {
			"access denied",
			"akamai",
			"reference #",
		},
		"Imperva Incapsula": {
			"incapsula incident id",
			"powered by incapsula",
			"_incap_",
		},
		"Sucuri": {
			"sucuri website firewall",
			"access denied - sucuri",
			"sucuri cloudproxy",
		},
		"ModSecurity": {
			"mod_security",
			"modsecurity",
			"this error was generated by mod_security",
		},
		"DDoS-Guard": {
			"ddos-guard",
		},
		"Wordfence": {
			"wordfence",
			"generated by wordfence",
		},
	}

	for wafName, signatures := range wafBodySignatures {
		for _, sig := range signatures {
			if strings.Contains(bodyLower, sig) {
				info.Detected = true
				info.Name = wafName
				info.Evidence = append(info.Evidence, fmt.Sprintf("Body contains: %s", sig))
				return info
			}
		}
	}

	return info
}

// TestHTTPMethods checks which HTTP methods are allowed
func TestHTTPMethods(host string) types.HTTPMethodsInfo {
	info := types.HTTPMethodsInfo{}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseURL := "https://" + host

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, method := range methods {
		wg.Add(1)
		go func(m string) {
			defer wg.Done()

			req, err := http.NewRequest(m, baseURL, nil)
			if err != nil {
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			result := types.HTTPMethodResult{
				Method:     m,
				StatusCode: resp.StatusCode,
				Allowed:    resp.StatusCode != 405 && resp.StatusCode != 501,
			}

			mu.Lock()
			info.Methods = append(info.Methods, result)
			if result.Allowed {
				info.Allowed = append(info.Allowed, m)
			}
			mu.Unlock()
		}(method)
	}

	wg.Wait()

	// Sort methods
	sort.Slice(info.Methods, func(i, j int) bool {
		return info.Methods[i].Method < info.Methods[j].Method
	})

	// Check for dangerous methods
	dangerousMethods := []string{"PUT", "DELETE", "TRACE", "CONNECT"}
	for _, allowed := range info.Allowed {
		for _, dangerous := range dangerousMethods {
			if allowed == dangerous {
				info.DangerousMethods = append(info.DangerousMethods, dangerous)
			}
		}
	}

	return info
}

// CheckCORS tests CORS configuration
func CheckCORS(host string) types.CORSInfo {
	info := types.CORSInfo{}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	baseURL := "https://" + host

	// Test with various origins
	testOrigins := []string{
		"https://evil.com",
		"https://attacker.com",
		"null",
		"https://" + host,
	}

	for _, origin := range testOrigins {
		req, _ := http.NewRequest("OPTIONS", baseURL, nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "GET")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		acao := resp.Header.Get("Access-Control-Allow-Origin")
		acac := resp.Header.Get("Access-Control-Allow-Credentials")
		acam := resp.Header.Get("Access-Control-Allow-Methods")
		acah := resp.Header.Get("Access-Control-Allow-Headers")

		if acao != "" {
			info.Enabled = true
			info.AllowOrigin = acao
			info.AllowCredentials = acac == "true"
			info.AllowMethods = acam
			info.AllowHeaders = acah

			// Check for misconfiguration
			if acao == "*" {
				info.Misconfigured = true
				info.Issues = append(info.Issues, "Wildcard origin (*) allows any domain")
			}
			if acao == "null" {
				info.Misconfigured = true
				info.Issues = append(info.Issues, "Null origin allowed - can be exploited via sandboxed iframes")
			}
			if acao == origin && origin != "https://"+host {
				info.Misconfigured = true
				info.Issues = append(info.Issues, fmt.Sprintf("Arbitrary origin reflected: %s", origin))
				if info.AllowCredentials {
					info.Issues = append(info.Issues, "CRITICAL: Credentials allowed with reflected origin")
				}
			}
			break
		}
	}

	return info
}

// MeasureLatency performs multiple latency measurements
func MeasureLatency(host string, samples int) types.LatencyInfo {
	info := types.LatencyInfo{
		Host:    host,
		Samples: samples,
	}

	var measurements []time.Duration

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
	}

	baseURL := "https://" + host

	for i := 0; i < samples; i++ {
		start := time.Now()

		resp, err := client.Get(baseURL)
		if err != nil {
			continue
		}
		resp.Body.Close()

		duration := time.Since(start)
		measurements = append(measurements, duration)

		// Small delay between samples
		time.Sleep(100 * time.Millisecond)
	}

	if len(measurements) == 0 {
		return info
	}

	// Calculate statistics
	var total time.Duration
	min := measurements[0]
	max := measurements[0]

	for _, m := range measurements {
		total += m
		if m < min {
			min = m
		}
		if m > max {
			max = m
		}
		info.Measurements = append(info.Measurements, m.String())
	}

	info.Min = min.String()
	info.Max = max.String()
	info.Average = (total / time.Duration(len(measurements))).String()

	// Calculate standard deviation
	avg := total / time.Duration(len(measurements))
	var sumSquares float64
	for _, m := range measurements {
		diff := float64(m - avg)
		sumSquares += diff * diff
	}
	variance := sumSquares / float64(len(measurements))
	stdDev := time.Duration(int64(variance) / int64(time.Millisecond))
	info.StdDev = stdDev.String()

	// Calculate jitter (average difference between consecutive measurements)
	if len(measurements) > 1 {
		var jitterTotal time.Duration
		for i := 1; i < len(measurements); i++ {
			diff := measurements[i] - measurements[i-1]
			if diff < 0 {
				diff = -diff
			}
			jitterTotal += diff
		}
		info.Jitter = (jitterTotal / time.Duration(len(measurements)-1)).String()
	}

	return info
}

// ParseSecurityTxt fetches and parses security.txt
func ParseSecurityTxt(host string) types.SecurityTxtInfo {
	info := types.SecurityTxtInfo{}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Try standard locations
	urls := []string{
		"https://" + host + "/.well-known/security.txt",
		"https://" + host + "/security.txt",
	}

	var body string
	for _, url := range urls {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			body = string(bodyBytes)
			info.Found = true
			info.Location = url
			break
		}
	}

	if !info.Found {
		return info
	}

	// Parse security.txt fields
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse field:value
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		field := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch field {
		case "contact":
			info.Contact = append(info.Contact, value)
		case "expires":
			info.Expires = value
			// Check if expired
			if exp, err := time.Parse(time.RFC3339, value); err == nil {
				if time.Now().After(exp) {
					info.Expired = true
				}
			}
		case "encryption":
			info.Encryption = value
		case "acknowledgments", "acknowledgements":
			info.Acknowledgments = value
		case "preferred-languages":
			info.PreferredLanguages = value
		case "canonical":
			info.Canonical = value
		case "policy":
			info.Policy = value
		case "hiring":
			info.Hiring = value
		}
	}

	// Validate required fields (per RFC 9116)
	if len(info.Contact) == 0 {
		info.Issues = append(info.Issues, "Missing required 'Contact' field")
	}
	if info.Expires == "" {
		info.Issues = append(info.Issues, "Missing required 'Expires' field")
	}
	if info.Expired {
		info.Issues = append(info.Issues, "security.txt has expired")
	}

	return info
}

// CheckIPv6Support tests if the host supports IPv6
func CheckIPv6Support(host string) types.IPv6Info {
	info := types.IPv6Info{
		Host: host,
	}

	// Check for AAAA records
	aaaa, err := net.LookupIP(host)
	if err != nil {
		return info
	}

	for _, ip := range aaaa {
		if ip.To4() == nil && ip.To16() != nil {
			info.HasAAAA = true
			info.Addresses = append(info.Addresses, ip.String())
		}
	}

	// Test IPv6 connectivity
	if info.HasAAAA && len(info.Addresses) > 0 {
		dialer := &net.Dialer{
			Timeout: 5 * time.Second,
		}

		ctx := context.Background()
		conn, err := dialer.DialContext(ctx, "tcp6", net.JoinHostPort(host, "443"))
		if err == nil {
			info.Reachable = true
			conn.Close()
		}
	}

	return info
}

// CheckRedirects follows and analyzes redirect chains
func CheckRedirects(host string) types.RedirectInfo {
	info := types.RedirectInfo{}

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	// Test both HTTP and HTTPS
	urls := []string{
		"http://" + host,
		"https://" + host,
	}

	for _, startURL := range urls {
		chain := []types.RedirectHop{}
		currentURL := startURL

		for i := 0; i < 10; i++ {
			req, _ := http.NewRequest("GET", currentURL, nil)

			resp, err := client.Transport.RoundTrip(req)
			if err != nil {
				break
			}

			hop := types.RedirectHop{
				URL:        currentURL,
				StatusCode: resp.StatusCode,
			}

			location := resp.Header.Get("Location")
			resp.Body.Close()

			chain = append(chain, hop)

			if resp.StatusCode >= 300 && resp.StatusCode < 400 && location != "" {
				// Resolve relative URLs
				if !strings.HasPrefix(location, "http") {
					if strings.HasPrefix(location, "/") {
						// Parse current URL to get base
						if baseReq, err := http.NewRequest("GET", currentURL, nil); err == nil {
							location = baseReq.URL.Scheme + "://" + baseReq.URL.Host + location
						}
					}
				}
				currentURL = location
			} else {
				break
			}
		}

		if startURL == "http://"+host {
			info.HTTPChain = chain
		} else {
			info.HTTPSChain = chain
		}
	}

	// Check for HTTPS upgrade
	if len(info.HTTPChain) > 0 && len(info.HTTPSChain) > 0 {
		lastHTTP := info.HTTPChain[len(info.HTTPChain)-1]
		if strings.HasPrefix(lastHTTP.URL, "https://") {
			info.HTTPSUpgrade = true
		}
	}

	return info
}

// AnalyzeServerBanner performs server banner analysis
func AnalyzeServerBanner(host string) types.BannerInfo {
	info := types.BannerInfo{}

	// Version regex for detecting version disclosure
	versionRegex := regexp.MustCompile(`[\d]+\.[\d]+(\.[\d]+)?`)

	// HTTP banner
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://" + host)
	if err == nil {
		info.Server = resp.Header.Get("Server")
		info.XPoweredBy = resp.Header.Get("X-Powered-By")
		resp.Body.Close()

		// Check for version disclosure
		if info.Server != "" && versionRegex.MatchString(info.Server) {
			info.VersionDisclosed = true
			info.Versions = append(info.Versions, "Server: "+info.Server)
		}
		if info.XPoweredBy != "" && versionRegex.MatchString(info.XPoweredBy) {
			info.VersionDisclosed = true
			info.Versions = append(info.Versions, "X-Powered-By: "+info.XPoweredBy)
		}
	}

	// SSH banner (port 22)
	conn, err := net.DialTimeout("tcp", host+":22", 5*time.Second)
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			info.SSH = strings.TrimSpace(string(buf[:n]))
			if versionRegex.MatchString(info.SSH) {
				info.VersionDisclosed = true
				info.Versions = append(info.Versions, "SSH: "+info.SSH)
			}
		}
		conn.Close()
	}

	// FTP banner (port 21)
	conn, err = net.DialTimeout("tcp", host+":21", 5*time.Second)
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			info.FTP = strings.TrimSpace(string(buf[:n]))
			if versionRegex.MatchString(info.FTP) {
				info.VersionDisclosed = true
				info.Versions = append(info.Versions, "FTP: "+info.FTP)
			}
		}
		conn.Close()
	}

	// SMTP banner (port 25)
	conn, err = net.DialTimeout("tcp", host+":25", 5*time.Second)
	if err == nil {
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 512)
		n, _ := conn.Read(buf)
		if n > 0 {
			info.SMTP = strings.TrimSpace(string(buf[:n]))
			if versionRegex.MatchString(info.SMTP) {
				info.VersionDisclosed = true
				info.Versions = append(info.Versions, "SMTP: "+info.SMTP)
			}
		}
		conn.Close()
	}

	return info
}
