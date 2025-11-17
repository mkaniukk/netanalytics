# NetAnalytics

A comprehensive network analysis tool written in Go that provides detailed information about hosts, including DNS records, TLS/SSL certificates, HTTP responses, geolocation, security headers, and infrastructure detection.

## Features

### DNS Analysis
- A, AAAA, CNAME, MX, NS, TXT, SOA, PTR records
- CAA (Certificate Authority Authorization) records
- Reverse DNS lookup
- Query timing

### TLS/SSL Certificate Analysis
- Protocol version (TLS 1.2/1.3)
- Cipher suite details
- Certificate information (subject, issuer, expiry)
- Subject Alternative Names (SAN)
- Serial number and certificate chain length
- OCSP stapling detection
- SSL/TLS grading (A+ to F) with security recommendations

### HTTP Analysis
- Status codes and response headers
- Server and OS detection
- Content type, encoding, and size
- Cookie analysis with security flags
- Technology stack detection:
  - CMS (WordPress, Drupal, Joomla, etc.)
  - Programming languages (PHP, Python, Ruby, etc.)
  - Frameworks (Laravel, Django, Express, etc.)
  - JavaScript libraries (jQuery, React, Vue, Angular)
  - Analytics platforms (Google Analytics, Tag Manager, Facebook Pixel)

### Infrastructure Detection
- **CDN Detection**: Cloudflare, Akamai, Fastly, AWS CloudFront, and 10+ more
- **Cloud Provider**: AWS, GCP, Azure, DigitalOcean, Oracle Cloud, Alibaba Cloud
- **Service Mesh**: Istio, Linkerd, Envoy, Consul Connect, Kuma, AWS App Mesh
- **Load Balancer**: NGINX, HAProxy, AWS ELB/ALB, GCP, Azure, Traefik
- **Container/Kubernetes**: Ingress controllers, container registries, orchestration platforms

### Geolocation
- IP address location (country, city)
- ISP and organization information
- ASN (Autonomous System Number)
- Hosting provider detection
- Proxy and mobile detection

### Network Information
- IP version (IPv4/IPv6)
- Reverse DNS lookup
- Port scanning (common ports: 21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443)

### Performance Metrics
- DNS lookup time
- TCP connection time
- TLS handshake time
- Time to first byte (TTFB)
- Total request time

### Security Analysis
- Security headers check (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS configuration grading
- Certificate expiration warnings
- Cookie security flags

## Installation

### Prerequisites
- Go 1.20 or higher
- Internet connection (for geolocation API)

### Build from source
```bash
git clone https://github.com/mkaniukk/netanalytics.git
cd netanalytics
go build -o netanalyze ./cmd/netanalyze
```

## Usage

### Basic usage
```bash
./netanalyze example.com
```

### With all features enabled
```bash
./netanalyze --geo --ports --perf example.com
```

### JSON output
```bash
./netanalyze --json example.com
```

### Command-line options
- `--json` - Output results in JSON format
- `--geo` - Include geolocation information
- `--ports` - Scan common ports
- `--perf` - Show performance metrics

## Examples

### Basic analysis
```bash
./netanalyze google.com
```

### Complete analysis with all features
```bash
./netanalyze --geo --ports --perf cloudflare.com
```

### Export to JSON file
```bash
./netanalyze --json --geo --ports --perf example.com > analysis.json
```

## Sample Output

```
==================================================
Host: example.com
Time: 2025-11-17T19:24:40+01:00
==================================================

DNS Records:
  A:      [93.184.216.34]
  AAAA:   [2606:2800:220:1:248:1893:25c8:1946]
  MX:     [mail.example.com.]
  NS:     [ns1.example.com. ns2.example.com.]
  CAA:    [issue: letsencrypt.org]
  Lookup: 45.123ms

TLS Certificate:
  Protocol:  TLS 1.3
  Cipher:    TLS_AES_128_GCM_SHA256
  Subject:   example.com
  Issuer:    Let's Encrypt Authority X3
  Key:       RSA 2048 bits
  Expires:   2026-01-15 12:00:00 +0000 UTC
  Serial:    1234567890
  Chain:     3 certificate(s)
  OCSP:      Enabled

  SSL Grade: A+ (Score: 100/100)
  Expires in: 60 days
  Strengths: [TLS 1.3 support Good cipher (AES-128-GCM) RSA 2048-bit key]

CDN Detection:
  Provider:  Cloudflare

HTTP Response:
  Status:   200
  Protocol: HTTP/3
  Server:   cloudflare
  Size:     12345 bytes
  Cookies:  [session (HttpOnly) (Secure) (SameSite=Lax)]

  Technology Stack:
    CMS:        WordPress
    Language:   [PHP]
    JavaScript: [jQuery React]
    Analytics:  [Google Analytics]

Performance Metrics:
  DNS Lookup:     1.5ms
  TCP Connect:    8.2ms
  TLS Handshake:  12.4ms
  First Byte:     125.3ms
  Total Time:     156.8ms

Security Headers:
  Strict-Transport-Security:     ✓  max-age=31536000
  Content-Security-Policy:       ⚠️  Not Set
  X-Frame-Options:               ✓  SAMEORIGIN
  X-Content-Type-Options:        ✓  nosniff
```

## Project Structure

```
netanalytics/
├── cmd/
│   └── netanalyze/
│       └── main.go           # Entry point and CLI handling
├── pkg/
│   ├── types/
│   │   └── types.go          # Data structure definitions
│   ├── dns/
│   │   └── dns.go            # DNS lookup functions
│   ├── tls/
│   │   └── tls.go            # TLS/SSL analysis
│   ├── http/
│   │   └── http.go           # HTTP analysis and tech detection
│   ├── network/
│   │   └── network.go        # Network utilities and geolocation
│   ├── detection/
│   │   └── detection.go      # Infrastructure detection (CDN, cloud, etc.)
│   └── output/
│       └── output.go         # Output formatting
├── go.mod                    # Go module definition
├── go.sum                    # Go dependencies
└── README.md                 # This file
```

## Dependencies

- `github.com/miekg/dns` - DNS query library

## API Usage

The tool uses the free ip-api.com service for geolocation data. No API key required for basic usage (limited to 45 requests per minute).

## License

MIT License
