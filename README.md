# NetAnalytics

A comprehensive network analysis tool written in Go that provides detailed information about hosts, including DNS records, TLS/SSL certificates, HTTP responses, geolocation, security headers, and infrastructure detection. Features intelligent analysis that highlights important security findings and unusual configurations.

## Features

### 🔍 Key Findings Analysis
- **Automatic security assessment** - Identifies critical issues, warnings, and positive configurations
- **Smart prioritization** - Highlights the most important findings first
- **Severity-based reporting** - Critical issues, warnings, positive findings, and informational notes
- **Actionable insights** - Provides context and recommendations for each finding

### DNS Analysis
- A, AAAA, CNAME, MX, NS, TXT, SOA, PTR records
- CAA (Certificate Authority Authorization) records
- Reverse DNS lookup
- Query timing
- IPv6 support detection
- SPF record analysis

### TLS/SSL Certificate Analysis
- Protocol version (TLS 1.2/1.3) with recommendations
- Cipher suite details with bit-strength analysis
- Certificate information (subject, issuer, expiry, validity period)
- **Detailed encryption information**:
  - Cipher strength (128-bit, 256-bit)
  - Key exchange mechanisms (ECDHE, DHE, TLS 1.3)
  - Perfect Forward Secrecy detection
  - Public key algorithms (RSA, ECDSA)
  - Key sizes (2048-bit, 4096-bit)
  - Signature algorithms (SHA256-RSA, ECDSA-SHA256)
- Subject Alternative Names (SAN)
- Serial number and certificate chain length
- OCSP stapling detection
- SSL/TLS grading (A+ to F) with security recommendations
- Certificate expiration warnings

### HTTP Analysis
- Status codes and response headers
- Server and OS detection **with version numbers**
- Content type, encoding, and size
- Cookie analysis with security flags (HttpOnly, Secure, SameSite)
- HTTP version detection (HTTP/1.1, HTTP/2, HTTP/3)
- Technology stack detection **with version extraction**:
  - CMS (WordPress, Drupal, Joomla) with versions
  - Web servers (Apache, Nginx, IIS) with versions
  - Programming languages (PHP, Python, Ruby) with versions
  - Frameworks (Laravel, Django, Express, etc.)
  - JavaScript libraries (jQuery, React, Vue, Angular) with versions
  - Analytics platforms (Google Analytics, Tag Manager, Facebook Pixel)

### Infrastructure Detection
- **CDN Detection**: Cloudflare, Akamai, Fastly, AWS CloudFront, and 10+ more
- **Cloud Provider**: AWS, GCP, Azure, DigitalOcean, Oracle Cloud, Alibaba Cloud
- **Service Mesh**: Istio, Linkerd, Envoy, Consul Connect, Kuma, AWS App Mesh
- **Load Balancer**: NGINX, HAProxy, AWS ELB/ALB, GCP, Azure, Traefik
- **Container/Kubernetes**: Ingress controllers, container registries, orchestration platforms

### Network Analysis
- IP version (IPv4/IPv6)
- Reverse DNS lookup
- Port scanning (common ports: 21, 22, 23, 25, 80, 443, 3306, 5432, 8080)
- **Traceroute** - Full network path with hop-by-hop analysis (requires `--trace` flag)
- Network hop count and latency per hop

### Geolocation
- IP address location (country, city)
- ISP and organization information
- ASN (Autonomous System Number)
- Hosting provider detection
- Proxy and mobile detection

### Performance Metrics
- DNS lookup time
- TCP connection time
- TLS handshake time
- Time to first byte (TTFB)
- Total request time
- Performance warnings for slow responses

### Security Analysis
- Security headers check (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS configuration grading
- Certificate expiration warnings
- Cookie security flags
- Missing security headers detection
- Development port exposure warnings
- **Clean output mode** - Hides non-detected items by default
- **Verbose mode** - Shows all details with `--verbose` flag

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
./netanalyze --geo --ports --perf --trace --verbose example.com
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
- `--trace` - Show network hops (traceroute)
- `--verbose` - Show all details including non-detected items

## Examples

### Basic analysis
```bash
./netanalyze google.com
```

### Complete analysis with all features
```bash
./netanalyze --geo --ports --perf --trace cloudflare.com
```

### Quick security audit
```bash
./netanalyze --verbose example.com
```

### Export to JSON file
```bash
./netanalyze --json --geo --ports --perf example.com > analysis.json
```

## Sample Output

```
==================================================
Host: google.com
Time: 2025-11-17T20:14:31+01:00
==================================================

🔍 Key Findings:

  ⚠️  [WARNING] Missing security headers: HSTS, CSP, X-Content-Type-Options
     → These headers provide additional security protection against common attacks

  ✅ [POSITIVE] Using modern TLS 1.3 protocol
     → TLS 1.3 provides improved security and performance

  ✅ [POSITIVE] Perfect Forward Secrecy enabled
     → Protects past sessions against future compromises of secret keys

  ✅ [POSITIVE] Excellent SSL configuration (Grade: A+)
     → SSL Labs grade: A+ with score 100/100

  ✅ [POSITIVE] Using HTTP/3 (QUIC) protocol
     → Modern protocol providing improved performance and reliability

  ✅ [POSITIVE] IPv6 support enabled
     → Site accessible via 1 IPv6 address(es)

  ✅ [POSITIVE] CAA records configured
     → Certificate Authority Authorization helps prevent unauthorized certificate issuance

  ✅ [POSITIVE] SPF record configured
     → Sender Policy Framework helps prevent email spoofing

  ℹ️  [INFO] Detected technologies: gws
     → Technology fingerprinting can help identify potential security updates needed


DNS Records:
  A:      [172.217.23.206]
  AAAA:   [2a00:1450:400e:805::200e]
  MX:     [smtp.google.com.]
  NS:     [ns1.google.com. ns2.google.com. ns3.google.com. ns4.google.com.]
  CAA:    [issue: pki.goog]
  Lookup: 86.523292ms

TLS Certificate:
  Protocol:  TLS 1.3
  Cipher:    TLS_AES_128_GCM_SHA256
  Strength:  128-bit
  Key Exch:  TLS 1.3 (Perfect Forward Secrecy)
  Subject:   *.google.com
  Issuer:    WR2
  Key Type:  ECDSA
  Pub Key:   ECDSA
  Signature: SHA256-RSA
  Valid From:2025-10-27 08:33:43 +0000 UTC
  Expires:   2026-01-19 08:33:42 +0000 UTC
  Serial:    209513414872567252831613141101590795633
  Chain:     3 certificate(s)

  SSL Grade: A+ (Score: 100/100)
  Expires in: 62 days
  Strengths: [TLS 1.3 support Good cipher (AES-128-GCM)]

Network Information:
  IP Version:   IPv4
  Reverse DNS:  ams16s37-in-f14.1e100.net.

HTTP Response:
  Status:   200
  Protocol: HTTP/3
  Server:   gws
  Tech:     [gws]
  Type:     text/html; charset=ISO-8859-1
  Latency:  142.793834ms
  Cookies:  [AEC (HttpOnly) (Secure) (SameSite=2)]

Security Headers:
  X-Frame-Options:               ✓  SAMEORIGIN
  X-XSS-Protection:              ✓  0
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
│   │   └── tls.go            # TLS/SSL analysis with grading
│   ├── http/
│   │   └── http.go           # HTTP analysis and tech detection
│   ├── network/
│   │   └── network.go        # Network utilities, geolocation, traceroute
│   ├── detection/
│   │   └── detection.go      # Infrastructure detection (CDN, cloud, etc.)
│   ├── analyzer/
│   │   └── analyzer.go       # Intelligent findings analysis
│   └── output/
│       └── output.go         # Output formatting
├── go.mod                    # Go module definition
├── go.sum                    # Go dependencies
└── README.md                 # This file
```

## Key Features Explained

### 🔍 Intelligent Findings Analysis
The tool automatically analyzes all collected data and highlights:
- **Critical Issues** (❌) - Expired certificates, severe security problems
- **Warnings** (⚠️) - Missing security headers, approaching certificate expiration, slow performance
- **Positive Findings** (✅) - Modern TLS, HTTP/3, strong encryption, CDN usage, proper DNS configuration
- **Informational** (ℹ️) - Detected technologies, configuration notes, infrastructure details

This makes it easy to quickly understand what matters most without reading through pages of detailed output.

### Version Detection
The tool intelligently extracts version numbers from:
- Server headers (e.g., `nginx/1.29.0`, `Apache/2.4.41`)
- X-Powered-By headers (e.g., `PHP/7.4.3`)
- Page content (JavaScript frameworks, CMS versions)
- Meta tags and embedded version strings

### Clean vs Verbose Mode
- **Default (Clean)**: Only shows detected items and important information
- **Verbose Mode** (`--verbose`): Shows all possible checks including "Not Set" items

This keeps the output focused and readable by default while still providing full details when needed.

## Dependencies

- `github.com/miekg/dns` - DNS query library

## API Usage

The tool uses the free ip-api.com service for geolocation data. No API key required for basic usage (limited to 45 requests per minute).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Changelog

### Recent Updates
- ✅ Added intelligent findings analysis with severity-based reporting
- ✅ Enhanced version detection for servers, frameworks, and libraries
- ✅ Added detailed encryption information (cipher strength, key exchange, PFS)
- ✅ Implemented traceroute functionality for network path analysis
- ✅ Added clean output mode (hides non-detected items by default)
- ✅ Enhanced security analysis with actionable recommendations
- ✅ Added support for HTTP/3, CAA records, and advanced infrastructure detection

## License

MIT License
