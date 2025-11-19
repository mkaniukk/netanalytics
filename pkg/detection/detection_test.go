package detection

import (
	"net/http"
	"testing"

	"netanalyze/pkg/types"
)

func TestDetectCDN(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		want     types.CDNInfo
		wantProv string
	}{
		{
			name: "Cloudflare via CF-Ray",
			headers: map[string]string{
				"CF-Ray": "some-ray-id",
			},
			wantProv: "Cloudflare",
		},
		{
			name: "CloudFront via X-Amz-Cf-Id",
			headers: map[string]string{
				"X-Amz-Cf-Id": "some-id",
			},
			wantProv: "CloudFront",
		},
		{
			name: "No CDN",
			headers: map[string]string{
				"Server": "Apache",
			},
			wantProv: "",
		},
		{
			name: "Varnish via Via header",
			headers: map[string]string{
				"Via": "1.1 varnish",
			},
			wantProv: "Varnish Cache",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}

			got := DetectCDN(header)

			if tt.wantProv != "" {
				if !got.Detected {
					t.Errorf("DetectCDN() detected = false, want true")
				}
				if got.Provider != tt.wantProv {
					t.Errorf("DetectCDN() provider = %v, want %v", got.Provider, tt.wantProv)
				}
			} else {
				if got.Detected {
					t.Errorf("DetectCDN() detected = true, want false")
				}
			}
		})
	}
}

func TestDetectCloudProvider(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		geoInfo  []types.GeoInfo
		wantProv string
	}{
		{
			name: "AWS via CloudFront headers",
			headers: map[string]string{
				"X-Amz-Cf-Id": "some-id",
			},
			wantProv: "AWS",
		},
		{
			name: "GCP via Server header",
			headers: map[string]string{
				"Server": "GFE/2.0",
			},
			wantProv: "Google Cloud Platform",
		},
		{
			name: "Azure via X-Azure-Ref",
			headers: map[string]string{
				"X-Azure-Ref": "some-ref",
			},
			wantProv: "Microsoft Azure",
		},
		{
			name: "DigitalOcean via GeoInfo",
			headers: map[string]string{},
			geoInfo: []types.GeoInfo{
				{Organization: "DigitalOcean, LLC"},
			},
			wantProv: "DigitalOcean",
		},
		{
			name: "No Cloud Provider",
			headers: map[string]string{
				"Server": "Apache",
			},
			wantProv: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}

			got := DetectCloudProvider(header, tt.geoInfo)

			if tt.wantProv != "" {
				if got.Provider != tt.wantProv {
					t.Errorf("DetectCloudProvider() provider = %v, want %v", got.Provider, tt.wantProv)
				}
			} else {
				if got.Provider != "" {
					t.Errorf("DetectCloudProvider() provider = %v, want empty", got.Provider)
				}
			}
		})
	}
}
