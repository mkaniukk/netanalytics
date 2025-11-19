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
