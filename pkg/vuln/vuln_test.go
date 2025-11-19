package vuln

import (
	"testing"

	"netanalyze/pkg/types"
)

func TestIdentifyComponents(t *testing.T) {
	tests := []struct {
		name     string
		httpInfo types.HTTPInfo
		tlsInfo  types.TLSInfo
		want     []types.SoftwareComponent
	}{
		{
			name: "Server Header",
			httpInfo: types.HTTPInfo{
				Server: "nginx/1.18.0",
			},
			want: []types.SoftwareComponent{
				{Name: "nginx", Version: "1.18.0", Source: "Server header"},
			},
		},
		{
			name: "X-Powered-By Header",
			httpInfo: types.HTTPInfo{
				PoweredBy: "PHP/7.4.3",
			},
			want: []types.SoftwareComponent{
				{Name: "PHP", Version: "7.4.3", Source: "X-Powered-By"},
			},
		},
		{
			name: "Tech Stack CMS",
			httpInfo: types.HTTPInfo{
				TechStack: types.TechFingerprint{
					CMS: "WordPress 5.8",
				},
			},
			want: []types.SoftwareComponent{
				{Name: "WordPress", Version: "5.8", Source: "CMS detection"},
			},
		},
		{
			name: "Multiple Components",
			httpInfo: types.HTTPInfo{
				Server: "Apache/2.4.41",
				TechStack: types.TechFingerprint{
					Language: []string{"PHP 7.3"},
				},
			},
			want: []types.SoftwareComponent{
				{Name: "Apache", Version: "2.4.41", Source: "Server header"},
				{Name: "PHP", Version: "7.3", Source: "Language detection"},
			},
		},
		{
			name: "No Version",
			httpInfo: types.HTTPInfo{
				Server: "nginx",
			},
			want: []types.SoftwareComponent{
				{Name: "nginx", Version: "", Source: "Server header"},
			},
		},
		{
			name: "WordPress Plugins",
			httpInfo: types.HTTPInfo{
				TechStack: types.TechFingerprint{
					Plugins: []string{"contact-form-7 5.4.2", "yoast-seo 16.7"},
				},
			},
			want: []types.SoftwareComponent{
				{Name: "contact-form-7", Version: "5.4.2", Source: "Plugin detection"},
				{Name: "yoast-seo", Version: "16.7", Source: "Plugin detection"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IdentifyComponents(tt.httpInfo, tt.tlsInfo)
			if len(got) != len(tt.want) {
				t.Errorf("IdentifyComponents() returned %d components, want %d", len(got), len(tt.want))
				return
			}

			for _, wantComp := range tt.want {
				found := false
				for _, gotComp := range got {
					if gotComp.Name == wantComp.Name && gotComp.Version == wantComp.Version && gotComp.Source == wantComp.Source {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("IdentifyComponents() missing component %v", wantComp)
				}
			}
		})
	}
}

func TestParseNameVersion(t *testing.T) {
	tests := []struct {
		input       string
		wantName    string
		wantVersion string
	}{
		{"nginx/1.18.0", "nginx", "1.18.0"},
		{"Apache/2.4.41 (Ubuntu)", "Apache", "2.4.41"},
		{"PHP 7.4.3", "PHP", "7.4.3"},
		{"WordPress 5.8", "WordPress", "5.8"},
		{"nginx", "nginx", ""},
		{"", "", ""},
		{"OpenSSL/1.1.1k", "OpenSSL", "1.1.1"},
		{"React 16.8.0", "React", "16.8.0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotName, gotVersion := parseNameVersion(tt.input)
			if gotName != tt.wantName {
				t.Errorf("parseNameVersion(%q) name = %q, want %q", tt.input, gotName, tt.wantName)
			}
			if gotVersion != tt.wantVersion {
				t.Errorf("parseNameVersion(%q) version = %q, want %q", tt.input, gotVersion, tt.wantVersion)
			}
		})
	}
}
