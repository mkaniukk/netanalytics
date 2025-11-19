package vuln

import (
	"encoding/json"
	"fmt"
	"io"
	nethttp "net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"netanalyze/pkg/types"
)

const (
	maxComponentsToQuery = 5
	maxCVEsPerComponent  = 3
	nvdEndpoint          = "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

var (
	versionPattern         = regexp.MustCompile(`(?i)^([a-z0-9._\- ]+?)[/ ]v?(\d+(?:\.\d+)+)`)
	trailingVersionPattern = regexp.MustCompile(`(?i)([a-z0-9._\- ]+?)[ ]+v?(\d+(?:\.\d+)+)$`)
)

// IdentifyComponents extracts recognizable software components from HTTP/TLS metadata for CVE lookups.
func IdentifyComponents(httpInfo types.HTTPInfo, tlsInfo types.TLSInfo) []types.SoftwareComponent {
	components := make(map[string]types.SoftwareComponent)

	add := func(raw, source string) {
		name, version := parseNameVersion(raw)
		if name == "" {
			return
		}
		key := strings.ToLower(strings.TrimSpace(name)) + "|" + strings.ToLower(version)
		if _, exists := components[key]; exists {
			return
		}
		components[key] = types.SoftwareComponent{
			Name:    strings.TrimSpace(name),
			Version: version,
			Source:  source,
		}
	}

	add(httpInfo.Server, "Server header")
	add(httpInfo.PoweredBy, "X-Powered-By")
	for _, tech := range httpInfo.Technology {
		add(tech, "Technology header")
	}

	if httpInfo.TechStack.CMS != "" {
		add(httpInfo.TechStack.CMS, "CMS detection")
	}
	for _, lang := range httpInfo.TechStack.Language {
		add(lang, "Language detection")
	}
	for _, framework := range httpInfo.TechStack.Framework {
		add(framework, "Framework detection")
	}
	for _, js := range httpInfo.TechStack.JavaScript {
		add(js, "JavaScript detection")
	}

	if tlsInfo.Subject != "" {
		add(tlsInfo.Subject, "Certificate subject")
	}
	if tlsInfo.Issuer != "" {
		add(tlsInfo.Issuer, "Certificate issuer")
	}

	out := make([]types.SoftwareComponent, 0, len(components))
	for _, component := range components {
		out = append(out, component)
	}
	return out
}

func parseNameVersion(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}

	if matches := versionPattern.FindStringSubmatch(raw); len(matches) > 2 {
		return strings.TrimSpace(matches[1]), matches[2]
	}
	if matches := trailingVersionPattern.FindStringSubmatch(raw); len(matches) > 2 {
		return strings.TrimSpace(matches[1]), matches[2]
	}

	if idx := strings.Index(raw, ":"); idx != -1 {
		name := strings.TrimSpace(raw[:idx])
		rest := strings.TrimSpace(raw[idx+1:])
		if matches := versionPattern.FindStringSubmatch(rest); len(matches) > 2 {
			return name, matches[2]
		}
		if rest != "" {
			return rest, ""
		}
		return name, ""
	}

	cleaned := strings.TrimSpace(raw)
	if slash := strings.Index(cleaned, "/"); slash != -1 {
		cleaned = cleaned[:slash]
	}
	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "" {
		cleaned = raw
	}
	return cleaned, ""
}

// LookupCVEs queries the public NVD API for CVEs related to detected components.
func LookupCVEs(components []types.SoftwareComponent) []types.CVEResult {
	client := &nethttp.Client{Timeout: 10 * time.Second}
	apiKey := os.Getenv("NVD_API_KEY")

	var results []types.CVEResult
	searched := 0
	seen := make(map[string]bool)

	for _, component := range components {
		if component.Name == "" || component.Version == "" {
			continue // require version to avoid noisy matches
		}
		key := strings.ToLower(component.Name + "|" + component.Version)
		if seen[key] {
			continue
		}
		seen[key] = true

		matches, err := queryNVD(client, apiKey, component)
		if err != nil || len(matches) == 0 {
			continue
		}

		results = append(results, types.CVEResult{Component: component, Matches: matches})
		searched++
		if searched >= maxComponentsToQuery {
			break
		}

		time.Sleep(500 * time.Millisecond) // avoid hammering the API
	}

	return results
}

func queryNVD(client *nethttp.Client, apiKey string, component types.SoftwareComponent) ([]types.CVEEntry, error) {
	query := strings.TrimSpace(component.Name + " " + component.Version)
	if query == "" {
		return nil, nil
	}

	params := url.Values{}
	params.Set("resultsPerPage", fmt.Sprintf("%d", maxCVEsPerComponent))
	params.Set("keywordSearch", query)

	req, err := nethttp.NewRequest(nethttp.MethodGet, nvdEndpoint+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "netanalyze/1.0")
	req.Header.Set("Accept", "application/json")
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != nethttp.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("nvd api returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}

	var parsed nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}

	var entries []types.CVEEntry
	for _, item := range parsed.Vulnerabilities {
		cve := item.CVE
		entry := types.CVEEntry{
			ID:          cve.ID,
			Description: pickDescription(cve.Descriptions),
			Published:   cve.Published,
			URL:         pickReference(cve.References),
		}
		entry.Severity, entry.CVSS = pickSeverity(cve.Metrics)
		entries = append(entries, entry)
		if len(entries) >= maxCVEsPerComponent {
			break
		}
	}

	return entries, nil
}

func pickDescription(descriptions []nvdDescription) string {
	for _, desc := range descriptions {
		if strings.EqualFold(desc.Lang, "en") {
			return desc.Value
		}
	}
	if len(descriptions) > 0 {
		return descriptions[0].Value
	}
	return ""
}

func pickReference(refs []nvdReference) string {
	if len(refs) == 0 {
		return ""
	}
	return refs[0].URL
}

func pickSeverity(metrics nvdMetrics) (string, float64) {
	if len(metrics.CvssMetricV31) > 0 {
		data := metrics.CvssMetricV31[0].CvssData
		return data.BaseSeverity, data.BaseScore
	}
	if len(metrics.CvssMetricV30) > 0 {
		data := metrics.CvssMetricV30[0].CvssData
		return data.BaseSeverity, data.BaseScore
	}
	if len(metrics.CvssMetricV2) > 0 {
		data := metrics.CvssMetricV2[0].CvssData
		return metrics.CvssMetricV2[0].BaseSeverity, data.BaseScore
	}
	return "", 0
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string           `json:"id"`
	Published    string           `json:"published"`
	Descriptions []nvdDescription `json:"descriptions"`
	Metrics      nvdMetrics       `json:"metrics"`
	References   []nvdReference   `json:"references"`
}

type nvdDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdReference struct {
	URL string `json:"url"`
}

type nvdMetrics struct {
	CvssMetricV31 []struct {
		CvssData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV31"`
	CvssMetricV30 []struct {
		CvssData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"cvssMetricV30"`
	CvssMetricV2 []struct {
		CvssData struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssData"`
		BaseSeverity string `json:"baseSeverity"`
	} `json:"cvssMetricV2"`
}
