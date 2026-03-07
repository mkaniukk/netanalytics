package content

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchResourceMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("User-agent: *"))
		case "/sitemap.xml":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<xml>...</xml>"))
		case "/.env":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("SECRET=key"))
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()

	client := server.Client()

	tests := []struct {
		name      string
		path      string
		wantFound bool
		wantSize  int64
	}{
		{"Found robots.txt", "/robots.txt", true, 13},
		{"Found sitemap.xml", "/sitemap.xml", true, 14},
		{"Found .env", "/.env", true, 10},
		{"Not Found", "/missing", false, 0},
		{"Forbidden", "/forbidden", false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, size := fetchResourceMetadata(client, server.URL+tt.path)
			if found != tt.wantFound {
				t.Errorf("fetchResourceMetadata() found = %v, want %v", found, tt.wantFound)
			}
			if found && size != tt.wantSize {
				t.Errorf("fetchResourceMetadata() size = %v, want %v", size, tt.wantSize)
			}
		})
	}
}

func TestFetchAndValidateSensitiveFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.env":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("DB_HOST=localhost\nDB_PASS=secret123"))
		case "/.git/HEAD":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ref: refs/heads/main"))
		case "/Dockerfile":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("FROM node:18\nRUN npm install"))
		case "/.env-fake":
			// Simulates soft 404 - returns HTML page
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<!DOCTYPE html><html><body>Page not found</body></html>"))
		case "/redirect-target":
			// This would be reached after redirect, but we don't follow redirects
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("homepage content"))
		case "/will-redirect":
			http.Redirect(w, r, "/redirect-target", http.StatusFound)
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := noRedirectClient(5 * time.Second)

	tests := []struct {
		name      string
		path      string
		wantFound bool
	}{
		{"Valid .env file", "/.env", true},
		{"Valid .git/HEAD", "/.git/HEAD", true},
		{"Valid Dockerfile", "/Dockerfile", true},
		{"Soft 404 (HTML response)", "/.env-fake", false},
		{"Redirect (not followed)", "/will-redirect", false},
		{"404 Not Found", "/missing", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found, _ := fetchAndValidateSensitiveFile(client, server.URL+tt.path, tt.path)
			if found != tt.wantFound {
				t.Errorf("fetchAndValidateSensitiveFile() found = %v, want %v", found, tt.wantFound)
			}
		})
	}
}

func TestContentSignatures(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content []byte
		want    bool
	}{
		{"Valid .env", "/.env", []byte("API_KEY=abc123\nDB_URL=postgres://"), true},
		{"Invalid .env (HTML)", "/.env", []byte("<html><body>Not found</body></html>"), false},
		{"Valid .git/HEAD", "/.git/HEAD", []byte("ref: refs/heads/main"), true},
		{"Invalid .git/HEAD", "/.git/HEAD", []byte("some random content"), false},
		{"Valid Dockerfile", "/Dockerfile", []byte("FROM ubuntu:20.04\nRUN apt-get update"), true},
		{"Invalid Dockerfile", "/Dockerfile", []byte("Just some text"), false},
		{"Invalid Dockerfile (HTML with COPY)", "/Dockerfile", []byte(`<!DOCTYPE html><html><body>{"action_menu_copy_button":"Copy"}</body></html>`), false},
		{"Valid package.json", "/package.json", []byte(`{"name": "myapp", "version": "1.0.0"}`), true},
		{"Invalid package.json", "/package.json", []byte(`{"random": "data"}`), false},
		{"Valid .htaccess", "/.htaccess", []byte("RewriteEngine On\nRewriteRule ^(.*)$"), true},
		{"Invalid .htaccess", "/.htaccess", []byte("<html>Error page</html>"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, exists := contentSignatures[tt.path]
			if !exists {
				t.Fatalf("No validator for path %s", tt.path)
			}
			got := validator(tt.content)
			if got != tt.want {
				t.Errorf("contentSignatures[%s]() = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestAnalyzeContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("User-agent: *"))
		case "/.env":
			// Return valid .env content
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("SECRET=key\nAPI_KEY=test123"))
		case "/wp-config.php.bak":
			// Return valid PHP backup content
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<?php\ndefine('DB_NAME', 'wordpress');\ndefine('DB_USER', 'admin');"))
		case "/.git/HEAD":
			// Return HTML (soft 404) - should NOT be detected
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<!DOCTYPE html><html><body>404</body></html>"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Extract host and protocol from server.URL (e.g., "http://127.0.0.1:12345")
	// Since AnalyzeContent takes host and protocol separately.
	// server.URL includes "http://"
	host := server.URL[7:] // remove http://

	info := AnalyzeContent(host, "http")

	if !info.RobotsTxt {
		t.Error("Expected RobotsTxt to be true")
	}

	foundEnv := false
	foundBackup := false
	foundGitHead := false
	for _, f := range info.ExposedFiles {
		if f == "/.env" {
			foundEnv = true
		}
		if f == "/wp-config.php.bak" {
			foundBackup = true
		}
		if f == "/.git/HEAD" {
			foundGitHead = true
		}
	}

	if !foundEnv {
		t.Error("Expected /.env to be in ExposedFiles")
	}
	if !foundBackup {
		t.Error("Expected /wp-config.php.bak to be in ExposedFiles")
	}
	if foundGitHead {
		t.Error("Expected /.git/HEAD NOT to be in ExposedFiles (soft 404 should be filtered)")
	}
}

func TestAnalyzeContentRedirectFalsePositive(t *testing.T) {
	// Test that redirects to homepage don't cause false positives
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("<html><body>Welcome to our site</body></html>"))
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("User-agent: *"))
		case "/.env", "/.htaccess", "/.git/HEAD", "/Dockerfile":
			// Redirect all sensitive files to homepage (common SPA behavior)
			http.Redirect(w, r, "/", http.StatusFound)
		default:
			http.Redirect(w, r, "/", http.StatusFound)
		}
	}))
	defer server.Close()

	host := server.URL[7:] // remove http://

	info := AnalyzeContent(host, "http")

	// None of the sensitive files should be detected
	if len(info.ExposedFiles) > 0 {
		t.Errorf("Expected no exposed files due to redirects, but found: %v", info.ExposedFiles)
	}
}
