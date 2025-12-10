package content

import (
	"net/http"
	"net/http/httptest"
	"testing"
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

func TestAnalyzeContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/robots.txt":
			w.WriteHeader(http.StatusOK)
		case "/.env":
			w.WriteHeader(http.StatusOK)
		case "/wp-config.php.bak":
			w.WriteHeader(http.StatusOK)
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
	for _, f := range info.ExposedFiles {
		if f == "/.env" {
			foundEnv = true
		}
		if f == "/wp-config.php.bak" {
			foundBackup = true
		}
	}

	if !foundEnv {
		t.Error("Expected /.env to be in ExposedFiles")
	}
	if !foundBackup {
		t.Error("Expected /wp-config.php.bak to be in ExposedFiles")
	}
}
