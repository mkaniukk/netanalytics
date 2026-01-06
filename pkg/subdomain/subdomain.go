package subdomain

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/mkaniukk/netanalytics/pkg/types"
)

// EnumerateSubdomains discovers subdomains using certificate transparency logs
func EnumerateSubdomains(domain string) types.SubdomainInfo {
	info := types.SubdomainInfo{
		Domain: domain,
	}

	// Collect subdomains from multiple sources
	subdomains := make(map[string]bool)
	var mu sync.Mutex

	var wg sync.WaitGroup

	// crt.sh - Certificate Transparency logs
	wg.Add(1)
	go func() {
		defer wg.Done()
		found := queryCrtSh(domain)
		mu.Lock()
		for _, sub := range found {
			subdomains[sub] = true
		}
		info.Sources = append(info.Sources, "crt.sh")
		mu.Unlock()
	}()

	wg.Wait()

	// Convert map to slice and sort
	for sub := range subdomains {
		// Clean and validate subdomain
		sub = cleanSubdomain(sub, domain)
		if sub != "" && isValidSubdomain(sub, domain) {
			info.Found = append(info.Found, sub)
		}
	}

	// Remove duplicates and sort
	info.Found = removeDuplicates(info.Found)
	sort.Strings(info.Found)

	info.Count = len(info.Found)

	// Resolve a sample of subdomains (limit to avoid timeouts)
	if len(info.Found) > 0 {
		maxResolve := 20
		if len(info.Found) < maxResolve {
			maxResolve = len(info.Found)
		}
		info.Resolved = resolveSubdomains(info.Found[:maxResolve])
	}

	return info
}

// queryCrtSh queries crt.sh for certificate transparency data
func queryCrtSh(domain string) []string {
	var subdomains []string

	client := &http.Client{Timeout: 30 * time.Second}
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	resp, err := client.Get(url)
	if err != nil {
		return subdomains
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return subdomains
	}

	var results []struct {
		CommonName string `json:"common_name"`
		NameValue  string `json:"name_value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		return subdomains
	}

	seen := make(map[string]bool)
	for _, result := range results {
		// Process common name
		if result.CommonName != "" {
			names := strings.Split(result.CommonName, "\n")
			for _, name := range names {
				name = strings.TrimSpace(strings.ToLower(name))
				name = strings.TrimPrefix(name, "*.")
				if !seen[name] {
					subdomains = append(subdomains, name)
					seen[name] = true
				}
			}
		}
		// Process name value (can contain multiple names)
		if result.NameValue != "" {
			names := strings.Split(result.NameValue, "\n")
			for _, name := range names {
				name = strings.TrimSpace(strings.ToLower(name))
				name = strings.TrimPrefix(name, "*.")
				if !seen[name] {
					subdomains = append(subdomains, name)
					seen[name] = true
				}
			}
		}
	}

	return subdomains
}

func cleanSubdomain(sub, baseDomain string) string {
	sub = strings.TrimSpace(strings.ToLower(sub))
	sub = strings.TrimPrefix(sub, "*.")
	sub = strings.TrimSuffix(sub, ".")

	// Must end with base domain
	if !strings.HasSuffix(sub, baseDomain) {
		return ""
	}

	return sub
}

func isValidSubdomain(sub, baseDomain string) bool {
	// Skip the base domain itself
	if sub == baseDomain {
		return false
	}

	// Must end with base domain
	if !strings.HasSuffix(sub, baseDomain) {
		return false
	}

	// Skip wildcard entries
	if strings.Contains(sub, "*") {
		return false
	}

	// Skip entries with spaces or special characters
	if strings.ContainsAny(sub, " \t\r\n@#$%^&()+={}[]|\\:;\"'<>,") {
		return false
	}

	return true
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}

func resolveSubdomains(subdomains []string) []types.SubdomainResolution {
	var resolved []types.SubdomainResolution
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent DNS queries
	semaphore := make(chan struct{}, 10)

	for _, sub := range subdomains {
		wg.Add(1)
		go func(subdomain string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			resolution := types.SubdomainResolution{
				Subdomain: subdomain,
			}

			// Resolve A records
			ips, err := net.LookupHost(subdomain)
			if err == nil && len(ips) > 0 {
				resolution.IPs = ips
				resolution.Active = true
			}

			// Resolve CNAME
			cname, err := net.LookupCNAME(subdomain)
			if err == nil && cname != "" && cname != subdomain+"." {
				resolution.CNAME = strings.TrimSuffix(cname, ".")
			}

			mu.Lock()
			resolved = append(resolved, resolution)
			mu.Unlock()
		}(sub)
	}

	wg.Wait()

	// Sort by subdomain name
	sort.Slice(resolved, func(i, j int) bool {
		return resolved[i].Subdomain < resolved[j].Subdomain
	})

	return resolved
}

// BruteForceSubdomains tries common subdomain prefixes
func BruteForceSubdomains(domain string, wordlist []string) []types.SubdomainResolution {
	var resolved []types.SubdomainResolution
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent DNS queries
	semaphore := make(chan struct{}, 20)

	for _, prefix := range wordlist {
		subdomain := prefix + "." + domain
		wg.Add(1)
		go func(sub string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			ips, err := net.LookupHost(sub)
			if err == nil && len(ips) > 0 {
				resolution := types.SubdomainResolution{
					Subdomain: sub,
					IPs:       ips,
					Active:    true,
				}

				cname, err := net.LookupCNAME(sub)
				if err == nil && cname != "" && cname != sub+"." {
					resolution.CNAME = strings.TrimSuffix(cname, ".")
				}

				mu.Lock()
				resolved = append(resolved, resolution)
				mu.Unlock()
			}
		}(subdomain)
	}

	wg.Wait()

	sort.Slice(resolved, func(i, j int) bool {
		return resolved[i].Subdomain < resolved[j].Subdomain
	})

	return resolved
}

// CommonSubdomainPrefixes returns a list of common subdomain prefixes
func CommonSubdomainPrefixes() []string {
	return []string{
		"www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
		"api", "dev", "staging", "test", "beta", "demo", "alpha",
		"admin", "portal", "dashboard", "panel", "console", "manage",
		"blog", "shop", "store", "m", "mobile", "app", "apps",
		"cdn", "static", "assets", "media", "images", "img", "files",
		"docs", "doc", "help", "support", "wiki", "kb", "faq",
		"vpn", "remote", "ssh", "sftp", "git", "gitlab", "github",
		"jenkins", "ci", "build", "deploy", "release",
		"db", "database", "mysql", "postgres", "redis", "mongo",
		"api-v1", "api-v2", "v1", "v2", "graphql", "rest",
		"auth", "login", "sso", "oauth", "id", "identity",
		"ns1", "ns2", "dns", "mx", "mx1", "mx2",
		"backup", "bak", "old", "new", "legacy", "archive",
		"status", "health", "monitoring", "metrics", "logs",
		"internal", "intranet", "extranet", "private", "public",
		"staging1", "staging2", "dev1", "dev2", "test1", "test2",
		"www1", "www2", "web", "web1", "web2",
		"secure", "ssl", "https", "payment", "pay", "checkout",
		"news", "events", "forum", "community", "social",
		"crm", "erp", "hr", "finance", "sales", "marketing",
	}
}
