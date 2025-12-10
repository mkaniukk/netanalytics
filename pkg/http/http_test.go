package http

import (
	"net/http"
	"testing"

	"github.com/mkaniukk/netanalytics/pkg/types"
)

func TestDetectOS(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		server  string
		want    string
	}{
		{
			name:    "Ubuntu",
			headers: http.Header{},
			server:  "Apache/2.4.41 (Ubuntu)",
			want:    "Ubuntu Linux",
		},
		{
			name:    "Windows IIS",
			headers: http.Header{},
			server:  "Microsoft-IIS/10.0",
			want:    "Windows (IIS)",
		},
		{
			name: "PHP via X-Powered-By",
			headers: http.Header{
				"X-Powered-By": []string{"PHP/7.4"},
			},
			server: "", // Empty server to test fallback
			want:   "Unix-like (PHP)",
		},
		{
			name: "ASP.NET via X-Powered-By",
			headers: http.Header{
				"X-Powered-By": []string{"ASP.NET"},
			},
			server: "Microsoft-IIS",
			want:   "Windows (IIS)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectOS(tt.headers, tt.server); got != tt.want {
				t.Errorf("detectOS() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectTechStack(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		body    string
		want    types.TechFingerprint
	}{
		{
			name: "WordPress",
			headers: http.Header{
				"Server": []string{"Apache"},
			},
			body: `<html><meta name="generator" content="WordPress 5.8" /></html>`,
			want: types.TechFingerprint{
				WebServer: "Apache",
				CMS:       "WordPress 5.8",
			},
		},
		{
			name: "React",
			headers: http.Header{
				"Server": []string{"nginx"},
			},
			body: `<html><script src="react.production.min.js"></script></html>`,
			want: types.TechFingerprint{
				WebServer:  "nginx",
				JavaScript: []string{"React"},
			},
		},
		{
			name: "HTTP/2",
			headers: http.Header{
				"X-Firefox-Spdy": []string{"h2"},
			},
			body: "",
			want: types.TechFingerprint{
				HTTPVersion: "HTTP/2",
			},
		},
		{
			name: "WordPress Plugins",
			headers: http.Header{},
			body: `<html>
				<link rel='stylesheet' id='contact-form-7-css'  href='https://example.com/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.4.2' media='all' />
				<script src='https://example.com/wp-content/plugins/yoast-seo/js/frontend.js?ver=16.7'></script>
			</html>`,
			want: types.TechFingerprint{
				CMS:     "WordPress",
				Plugins: []string{"contact-form-7 5.4.2", "yoast-seo 16.7"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectTechStack(tt.headers, tt.body)
			if got.WebServer != tt.want.WebServer {
				t.Errorf("WebServer = %v, want %v", got.WebServer, tt.want.WebServer)
			}
			if got.CMS != tt.want.CMS {
				t.Errorf("CMS = %v, want %v", got.CMS, tt.want.CMS)
			}
			if got.HTTPVersion != tt.want.HTTPVersion {
				t.Errorf("HTTPVersion = %v, want %v", got.HTTPVersion, tt.want.HTTPVersion)
			}
			if len(tt.want.JavaScript) > 0 {
				found := false
				for _, j := range got.JavaScript {
					if j == tt.want.JavaScript[0] {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("JavaScript missing %v", tt.want.JavaScript[0])
				}
			}
			if len(tt.want.Plugins) > 0 {
				for _, wantP := range tt.want.Plugins {
					found := false
					for _, gotP := range got.Plugins {
						if gotP == wantP {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Plugins missing %v, got %v", wantP, got.Plugins)
					}
				}
			}
		})
	}
}
