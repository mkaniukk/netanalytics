package whois

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/mkaniukk/netanalytics/pkg/types"
)

// Common WHOIS servers by TLD
var whoisServers = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.pir.org",
	"info": "whois.afilias.net",
	"io":   "whois.nic.io",
	"co":   "whois.nic.co",
	"me":   "whois.nic.me",
	"biz":  "whois.biz",
	"us":   "whois.nic.us",
	"uk":   "whois.nic.uk",
	"de":   "whois.denic.de",
	"eu":   "whois.eu",
	"fr":   "whois.nic.fr",
	"nl":   "whois.sidn.nl",
	"au":   "whois.auda.org.au",
	"ca":   "whois.cira.ca",
	"ru":   "whois.tcinet.ru",
	"ch":   "whois.nic.ch",
	"at":   "whois.nic.at",
	"be":   "whois.dns.be",
	"jp":   "whois.jprs.jp",
	"kr":   "whois.kr",
	"cn":   "whois.cnnic.cn",
	"in":   "whois.registry.in",
	"pl":   "whois.dns.pl",
	"se":   "whois.iis.se",
	"no":   "whois.norid.no",
	"fi":   "whois.fi",
	"dk":   "whois.dk-hostmaster.dk",
	"es":   "whois.nic.es",
	"it":   "whois.nic.it",
	"pt":   "whois.dns.pt",
	"br":   "whois.registro.br",
	"mx":   "whois.mx",
	"nz":   "whois.srs.net.nz",
	"za":   "whois.registry.net.za",
	"edu":  "whois.educause.edu",
	"gov":  "whois.dotgov.gov",
}

// LookupWHOIS performs a WHOIS query for the given domain
func LookupWHOIS(domain string) types.WHOISInfo {
	info := types.WHOISInfo{}

	// Extract TLD
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return info
	}
	tld := parts[len(parts)-1]

	// Get WHOIS server
	server, ok := whoisServers[strings.ToLower(tld)]
	if !ok {
		server = "whois.iana.org"
	}

	// Query WHOIS server
	rawData := queryWhois(server, domain)
	if rawData == "" {
		return info
	}

	// Parse response
	info = parseWhoisResponse(rawData)
	info.RawData = rawData

	return info
}

func queryWhois(server, domain string) string {
	conn, err := net.DialTimeout("tcp", server+":43", 10*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send query
	query := domain + "\r\n"
	if _, err := conn.Write([]byte(query)); err != nil {
		return ""
	}

	// Read response
	var result strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		result.WriteString(scanner.Text() + "\n")
	}

	return result.String()
}

func parseWhoisResponse(data string) types.WHOISInfo {
	info := types.WHOISInfo{}

	lines := strings.Split(data, "\n")

	// Common patterns for different registrars
	registrarPatterns := []string{
		`(?i)registrar:\s*(.+)`,
		`(?i)sponsoring registrar:\s*(.+)`,
		`(?i)registrar name:\s*(.+)`,
	}
	creationPatterns := []string{
		`(?i)creation date:\s*(.+)`,
		`(?i)created:\s*(.+)`,
		`(?i)created date:\s*(.+)`,
		`(?i)registration date:\s*(.+)`,
		`(?i)domain registration date:\s*(.+)`,
	}
	expiryPatterns := []string{
		`(?i)expir(?:y|ation) date:\s*(.+)`,
		`(?i)registry expiry date:\s*(.+)`,
		`(?i)registrar registration expiration date:\s*(.+)`,
		`(?i)paid-till:\s*(.+)`,
		`(?i)expires:\s*(.+)`,
	}
	nsPatterns := []string{
		`(?i)name server:\s*(.+)`,
		`(?i)nserver:\s*(.+)`,
	}
	registrantPatterns := []string{
		`(?i)registrant(?:\s+name)?:\s*(.+)`,
		`(?i)registrant organization:\s*(.+)`,
	}
	updatedPatterns := []string{
		`(?i)updated date:\s*(.+)`,
		`(?i)last updated:\s*(.+)`,
		`(?i)last modified:\s*(.+)`,
	}
	statusPatterns := []string{
		`(?i)domain status:\s*(.+)`,
		`(?i)status:\s*(.+)`,
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Registrar
		if info.Registrar == "" {
			for _, pattern := range registrarPatterns {
				if re := regexp.MustCompile(pattern); re.MatchString(line) {
					match := re.FindStringSubmatch(line)
					if len(match) > 1 {
						info.Registrar = strings.TrimSpace(match[1])
						break
					}
				}
			}
		}

		// Creation Date
		if info.CreationDate == "" {
			for _, pattern := range creationPatterns {
				if re := regexp.MustCompile(pattern); re.MatchString(line) {
					match := re.FindStringSubmatch(line)
					if len(match) > 1 {
						info.CreationDate = strings.TrimSpace(match[1])
						break
					}
				}
			}
		}

		// Expiry Date
		if info.ExpiryDate == "" {
			for _, pattern := range expiryPatterns {
				if re := regexp.MustCompile(pattern); re.MatchString(line) {
					match := re.FindStringSubmatch(line)
					if len(match) > 1 {
						info.ExpiryDate = strings.TrimSpace(match[1])
						break
					}
				}
			}
		}

		// Updated Date
		if info.UpdatedDate == "" {
			for _, pattern := range updatedPatterns {
				if re := regexp.MustCompile(pattern); re.MatchString(line) {
					match := re.FindStringSubmatch(line)
					if len(match) > 1 {
						info.UpdatedDate = strings.TrimSpace(match[1])
						break
					}
				}
			}
		}

		// Name Servers
		for _, pattern := range nsPatterns {
			if re := regexp.MustCompile(pattern); re.MatchString(line) {
				match := re.FindStringSubmatch(line)
				if len(match) > 1 {
					ns := strings.TrimSpace(strings.ToLower(match[1]))
					if ns != "" && !contains(info.NameServers, ns) {
						info.NameServers = append(info.NameServers, ns)
					}
				}
			}
		}

		// Registrant
		if info.Registrant == "" {
			for _, pattern := range registrantPatterns {
				if re := regexp.MustCompile(pattern); re.MatchString(line) {
					match := re.FindStringSubmatch(line)
					if len(match) > 1 {
						val := strings.TrimSpace(match[1])
						if val != "" && !strings.Contains(strings.ToLower(val), "redacted") &&
							!strings.Contains(strings.ToLower(val), "privacy") {
							info.Registrant = val
							break
						}
					}
				}
			}
		}

		// Domain Status
		for _, pattern := range statusPatterns {
			if re := regexp.MustCompile(pattern); re.MatchString(line) {
				match := re.FindStringSubmatch(line)
				if len(match) > 1 {
					status := strings.TrimSpace(match[1])
					// Extract just the status code (remove URLs)
					if spaceIdx := strings.Index(status, " "); spaceIdx > 0 {
						status = status[:spaceIdx]
					}
					if status != "" && !contains(info.DomainStatus, status) {
						info.DomainStatus = append(info.DomainStatus, status)
					}
				}
			}
		}
	}

	// Calculate domain age
	if info.CreationDate != "" {
		if age := calculateDomainAge(info.CreationDate); age != "" {
			info.DomainAge = age
		}
	}

	return info
}

func calculateDomainAge(creationDate string) string {
	// Common date formats
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05-07:00",
		"2006-01-02",
		"02-Jan-2006",
		"2006.01.02",
		"02/01/2006",
		"01/02/2006",
		"2006/01/02",
		time.RFC3339,
	}

	var created time.Time
	var err error
	for _, format := range formats {
		created, err = time.Parse(format, strings.TrimSpace(creationDate))
		if err == nil {
			break
		}
	}

	if err != nil {
		return ""
	}

	now := time.Now()
	diff := now.Sub(created)
	years := int(diff.Hours() / 24 / 365)
	months := int(diff.Hours()/24/30) % 12

	if years > 0 {
		return fmt.Sprintf("%d years, %d months", years, months)
	}
	if months > 0 {
		return fmt.Sprintf("%d months", months)
	}
	days := int(diff.Hours() / 24)
	return fmt.Sprintf("%d days", days)
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
