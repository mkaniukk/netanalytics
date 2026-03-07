package content

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mkaniukk/netanalytics/pkg/types"
)

// contentSignatures maps file paths to validation functions that check if content is genuine
var contentSignatures = map[string]func([]byte) bool{
	"/.env": func(b []byte) bool {
		// .env files typically contain KEY=value pairs
		s := string(b)
		return strings.Contains(s, "=") && !strings.Contains(s, "<html") && !strings.Contains(s, "<!DOCTYPE")
	},
	"/.htaccess": func(b []byte) bool {
		// Apache config directives
		s := strings.ToLower(string(b))
		return (strings.Contains(s, "rewrite") || strings.Contains(s, "deny") ||
			strings.Contains(s, "allow") || strings.Contains(s, "redirect") ||
			strings.Contains(s, "options") || strings.Contains(s, "authtype")) &&
			!strings.Contains(s, "<html") && !strings.Contains(s, "<!doctype")
	},
	"/.htpasswd": func(b []byte) bool {
		// htpasswd format: username:password_hash
		s := string(b)
		lines := strings.Split(s, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, ":") && !strings.Contains(line, "<") {
				return true
			}
		}
		return false
	},
	"/.git/HEAD": func(b []byte) bool {
		s := string(b)
		return strings.HasPrefix(s, "ref: refs/") || len(s) == 40 || len(s) == 41 // SHA hash
	},
	"/.svn/HEAD": func(b []byte) bool {
		// SVN format indicator
		return len(b) > 0 && !strings.Contains(string(b), "<html")
	},
	"/nginx.conf": func(b []byte) bool {
		s := strings.ToLower(string(b))
		return (strings.Contains(s, "server") || strings.Contains(s, "location") ||
			strings.Contains(s, "upstream") || strings.Contains(s, "http {")) &&
			!strings.Contains(s, "<!doctype")
	},
	"/web.config": func(b []byte) bool {
		s := string(b)
		return strings.Contains(s, "<configuration") || strings.Contains(s, "<system.web")
	},
	"/phpinfo.php": func(b []byte) bool {
		s := string(b)
		return strings.Contains(s, "PHP Version") || strings.Contains(s, "phpinfo()")
	},
	"/info.php": func(b []byte) bool {
		s := string(b)
		return strings.Contains(s, "PHP Version") || strings.Contains(s, "phpinfo()")
	},
	"/.DS_Store": func(b []byte) bool {
		// DS_Store files start with specific magic bytes
		return len(b) >= 8 && bytes.HasPrefix(b, []byte{0x00, 0x00, 0x00, 0x01})
	},
	"/Dockerfile": func(b []byte) bool {
		s := string(b)
		sLower := strings.ToLower(s)
		// Reject HTML content
		if strings.Contains(sLower, "<!doctype") || strings.Contains(sLower, "<html") {
			return false
		}
		sUpper := strings.ToUpper(s)
		// Dockerfile commands typically appear at the start of lines
		lines := strings.Split(s, "\n")
		dockerCommands := 0
		for _, line := range lines {
			trimmed := strings.TrimSpace(strings.ToUpper(line))
			if strings.HasPrefix(trimmed, "FROM ") ||
				strings.HasPrefix(trimmed, "RUN ") ||
				strings.HasPrefix(trimmed, "COPY ") ||
				strings.HasPrefix(trimmed, "CMD ") ||
				strings.HasPrefix(trimmed, "ENTRYPOINT ") ||
				strings.HasPrefix(trimmed, "WORKDIR ") ||
				strings.HasPrefix(trimmed, "ENV ") ||
				strings.HasPrefix(trimmed, "EXPOSE ") ||
				strings.HasPrefix(trimmed, "ARG ") ||
				strings.HasPrefix(trimmed, "LABEL ") ||
				strings.HasPrefix(trimmed, "ADD ") ||
				strings.HasPrefix(trimmed, "USER ") {
				dockerCommands++
			}
		}
		// Require at least one valid Docker command at line start, and FROM must exist
		return dockerCommands >= 1 && strings.Contains(sUpper, "\nFROM ") || strings.HasPrefix(sUpper, "FROM ")
	},
	"/docker-compose.yml": func(b []byte) bool {
		s := strings.ToLower(string(b))
		return (strings.Contains(s, "services:") || strings.Contains(s, "version:")) &&
			!strings.Contains(s, "<html")
	},
	"/package.json": func(b []byte) bool {
		s := string(b)
		return strings.Contains(s, `"name"`) && strings.Contains(s, `"version"`)
	},
	"/composer.json": func(b []byte) bool {
		s := string(b)
		return strings.Contains(s, `"name"`) || strings.Contains(s, `"require"`)
	},
	"/Gemfile": func(b []byte) bool {
		s := string(b)
		return strings.Contains(s, "source") && strings.Contains(s, "gem ")
	},
	"/requirements.txt": func(b []byte) bool {
		s := string(b)
		// Should have package names, possibly with versions
		lines := strings.Split(s, "\n")
		validLines := 0
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && !strings.Contains(line, "<html") {
				validLines++
			}
		}
		return validLines > 0 && !strings.Contains(s, "<!DOCTYPE")
	},
	"/wp-config.php.bak": func(b []byte) bool {
		s := string(b)
		return strings.Contains(s, "DB_NAME") || strings.Contains(s, "DB_USER") ||
			strings.Contains(s, "<?php")
	},
	"/config.php.bak": func(b []byte) bool {
		s := string(b)
		return strings.Contains(s, "<?php") && !strings.Contains(s, "<!DOCTYPE")
	},
	"/error.log": func(b []byte) bool {
		s := strings.ToLower(string(b))
		return (strings.Contains(s, "error") || strings.Contains(s, "warning") ||
			strings.Contains(s, "fatal") || strings.Contains(s, "[")) &&
			!strings.Contains(s, "<!doctype")
	},
	"/debug.log": func(b []byte) bool {
		s := strings.ToLower(string(b))
		return (strings.Contains(s, "debug") || strings.Contains(s, "error") ||
			strings.Contains(s, "warning") || strings.Contains(s, "[")) &&
			!strings.Contains(s, "<!doctype")
	},
}

// noRedirectClient creates an HTTP client that doesn't follow redirects
func noRedirectClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}

func fetchResourceMetadata(client *http.Client, url string) (bool, int64) {
	resp, err := client.Head(url)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if resp.ContentLength >= 0 {
				return true, resp.ContentLength
			}
			// Need to fall back to GET to determine size
		} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return false, 0
		}
	}

	resp, err = client.Get(url)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, 0
	}
	size, _ := io.Copy(io.Discard, resp.Body)
	return true, size
}

// fetchAndValidateSensitiveFile checks if a sensitive file exists and contains valid content
// Returns (found, size) - found is true only if file exists AND content validates
func fetchAndValidateSensitiveFile(client *http.Client, url string, path string) (bool, int64) {
	resp, err := client.Get(url)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	// Must be exactly 200 OK (client doesn't follow redirects)
	if resp.StatusCode != http.StatusOK {
		return false, 0
	}

	// Read content (limit to 64KB to avoid memory issues)
	content, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return false, 0
	}

	size := int64(len(content))

	// If we have a signature validator for this file type, use it
	if validator, exists := contentSignatures[path]; exists {
		if !validator(content) {
			return false, 0 // Content doesn't match expected format
		}
	} else {
		// For files without specific validators, at minimum check it's not HTML
		s := strings.ToLower(string(content))
		if strings.Contains(s, "<!doctype html") || strings.Contains(s, "<html") {
			return false, 0 // Likely a soft 404 or redirect to homepage
		}
	}

	return true, size
}

func AnalyzeContent(host string, protocol string) types.ContentInfo {
	info := types.ContentInfo{}

	// Determine base URL
	baseURL := "https://" + host
	if protocol == "http" {
		baseURL = "http://" + host
	}

	// Standard client for general resources (follows redirects)
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Non-redirect client for sensitive file detection (prevents false positives)
	sensitiveClient := noRedirectClient(5 * time.Second)

	// Check robots.txt
	if found, size := fetchResourceMetadata(client, baseURL+"/robots.txt"); found {
		info.RobotsTxt = true
		info.RobotsSize = size
	}

	// Check sitemap.xml
	if found, size := fetchResourceMetadata(client, baseURL+"/sitemap.xml"); found {
		info.SitemapXml = true
		info.SitemapSize = size
	}

	// Check security.txt (standard locations)
	locations := []string{
		"/.well-known/security.txt",
		"/security.txt",
	}

	for _, loc := range locations {
		if found, size := fetchResourceMetadata(client, baseURL+loc); found {
			info.SecurityTxt = true
			info.SecuritySize = size
			break
		}
	}

	// Check for exposed sensitive files (using strict validation to avoid false positives)
	exposedFiles := []string{
		"/.htaccess",
		"/.htpasswd",
		"/.env",
		"/nginx.conf",
		"/web.config",
		"/server-status",
		"/nginx_status",
		"/.git/HEAD",
		"/phpinfo.php",
		"/info.php",
		"/.DS_Store",
		"/.svn/HEAD",
		"/Dockerfile",
		"/docker-compose.yml",
		"/package.json",
		"/composer.json",
		"/Gemfile",
		"/requirements.txt",
		"/wp-config.php.bak",
		"/config.php.bak",
		"/README.md",
		"/LICENSE",
		"/CHANGELOG.md",
		"/error.log",
		"/debug.log",
	}

	for _, file := range exposedFiles {
		if found, _ := fetchAndValidateSensitiveFile(sensitiveClient, baseURL+file, file); found {
			info.ExposedFiles = append(info.ExposedFiles, file)
		}
	}

	return info
}
