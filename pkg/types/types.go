package types

import "net/http"

type DNSInfo struct {
	A        []string
	AAAA     []string
	CNAME    []string
	MX       []string
	NS       []string
	TXT      []string
	SOA      string
	Reverse  []string
	CAA      []string
	Duration string
}

type TLSInfo struct {
	Version        string
	CipherSuite    string
	Subject        string
	Issuer         string
	Expiry         string
	NotBefore      string
	KeyType        string
	KeySize        int
	SignatureAlgo  string
	PublicKeyAlgo  string
	SAN            []string
	SerialNumber   string
	ChainLength    int
	OCSPStapling   bool
	CipherStrength string
	KeyExchange    string
}

type HTTPInfo struct {
	Status          int
	Server          string
	OS              string
	PoweredBy       string
	Technology      []string
	ContentType     string
	Encoding        string
	ContentLength   int64
	Duration        string
	RedirectChain   []string
	SecurityHeaders map[string]string
	TechStack       TechFingerprint
	Headers         http.Header
	Cookies         []string
}

type GeoInfo struct {
	IP           string `json:"ip"`
	Country      string `json:"country"`
	City         string `json:"city"`
	Organization string `json:"organization"`
	ASN          string `json:"asn"`
	ISP          string `json:"isp"`
	Hosting      string `json:"hosting"`
	Proxy        bool   `json:"proxy"`
	Mobile       bool   `json:"mobile"`
}

type PortInfo struct {
	Port    int    `json:"port"`
	Status  string `json:"status"`
	Service string `json:"service"`
}

type PerformanceInfo struct {
	DNSLookup    string `json:"dns_lookup"`
	TCPConnect   string `json:"tcp_connect"`
	TLSHandshake string `json:"tls_handshake"`
	FirstByte    string `json:"first_byte"`
	TotalTime    string `json:"total_time"`
}

type SSLGrade struct {
	Grade           string   `json:"grade"`
	Score           int      `json:"score"`
	CertExpiresDays int      `json:"cert_expires_days"`
	Issues          []string `json:"issues"`
	Strengths       []string `json:"strengths"`
}

type CDNInfo struct {
	Detected bool     `json:"detected"`
	Provider string   `json:"provider"`
	Headers  []string `json:"headers"`
}

type TechFingerprint struct {
	WebServer   string   `json:"web_server"`
	HTTPVersion string   `json:"http_version"`
	Language    []string `json:"language"`
	Framework   []string `json:"framework"`
	CMS         string   `json:"cms"`
	JavaScript  []string `json:"javascript"`
	Analytics   []string `json:"analytics"`
	Plugins     []string `json:"plugins"`
}

type ServiceMeshInfo struct {
	Detected bool     `json:"detected"`
	Type     string   `json:"type"`
	Version  string   `json:"version"`
	TraceID  string   `json:"trace_id"`
	Headers  []string `json:"headers"`
}

type LoadBalancerInfo struct {
	Detected bool     `json:"detected"`
	Type     string   `json:"type"`
	Backend  string   `json:"backend"`
	Headers  []string `json:"headers"`
}

type ContainerInfo struct {
	Detected     bool     `json:"detected"`
	Orchestrator string   `json:"orchestrator"`
	Platform     string   `json:"platform"`
	Ingress      string   `json:"ingress"`
	Registry     string   `json:"registry"`
	Headers      []string `json:"headers"`
}

type CloudProviderInfo struct {
	Provider string   `json:"provider"`
	Region   string   `json:"region"`
	Service  []string `json:"service"`
	Headers  []string `json:"headers"`
}

type WHOISInfo struct {
	Registrar    string   `json:"registrar"`
	Registrant   string   `json:"registrant"`
	CreationDate string   `json:"creation_date"`
	UpdatedDate  string   `json:"updated_date"`
	ExpiryDate   string   `json:"expiry_date"`
	DomainAge    string   `json:"domain_age"`
	NameServers  []string `json:"name_servers"`
	DomainStatus []string `json:"domain_status"`
	RawData      string   `json:"raw_data,omitempty"`
}

type HopInfo struct {
	Hop      int
	IP       string
	Hostname string
	RTT      string
}

type NetworkInfo struct {
	ASN        string
	ASNOrg     string
	IPVersion  string
	ReverseDNS string
	HopCount   int
	Hops       []HopInfo
}

type Finding struct {
	Severity string // "critical", "warning", "info", "positive"
	Category string // "Security", "Performance", "Configuration", etc.
	Message  string
	Detail   string
}

type ContentInfo struct {
	RobotsTxt    bool     `json:"robots_txt"`
	SitemapXml   bool     `json:"sitemap_xml"`
	SecurityTxt  bool     `json:"security_txt"`
	RobotsSize   int64    `json:"robots_size"`
	SitemapSize  int64    `json:"sitemap_size"`
	SecuritySize int64    `json:"security_size"`
	ExposedFiles []string `json:"exposed_files"`
}

type EmailSecurityInfo struct {
	SPF         bool   `json:"spf"`
	SPFRecord   string `json:"spf_record"`
	DMARC       bool   `json:"dmarc"`
	DMARCRecord string `json:"dmarc_record"`
	DMARCPolicy string `json:"dmarc_policy"`
}

type SoftwareComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  string `json:"source"`
}

type CVEEntry struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	Description string  `json:"description"`
	Published   string  `json:"published"`
	URL         string  `json:"url"`
}

type CVEResult struct {
	Component SoftwareComponent `json:"component"`
	Matches   []CVEEntry        `json:"matches"`
}

// SubdomainInfo contains subdomain enumeration results
type SubdomainInfo struct {
	Domain   string                `json:"domain"`
	Count    int                   `json:"count"`
	Found    []string              `json:"found"`
	Resolved []SubdomainResolution `json:"resolved"`
	Sources  []string              `json:"sources"`
}

type SubdomainResolution struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips"`
	CNAME     string   `json:"cname,omitempty"`
	Active    bool     `json:"active"`
}

// DNSSECInfo contains DNSSEC validation results
type DNSSECInfo struct {
	Domain    string   `json:"domain"`
	Enabled   bool     `json:"enabled"`
	Valid     bool     `json:"valid"`
	Algorithm string   `json:"algorithm,omitempty"`
	KeyType   string   `json:"key_type,omitempty"`
	Keys      []string `json:"keys,omitempty"`
	DSRecords []string `json:"ds_records,omitempty"`
}

// WAFInfo contains WAF detection results
type WAFInfo struct {
	Detected bool     `json:"detected"`
	Name     string   `json:"name,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

// HTTPMethodsInfo contains HTTP methods testing results
type HTTPMethodsInfo struct {
	Methods          []HTTPMethodResult `json:"methods"`
	Allowed          []string           `json:"allowed"`
	DangerousMethods []string           `json:"dangerous_methods,omitempty"`
}

type HTTPMethodResult struct {
	Method     string `json:"method"`
	StatusCode int    `json:"status_code"`
	Allowed    bool   `json:"allowed"`
}

// CORSInfo contains CORS configuration analysis
type CORSInfo struct {
	Enabled          bool     `json:"enabled"`
	AllowOrigin      string   `json:"allow_origin,omitempty"`
	AllowCredentials bool     `json:"allow_credentials"`
	AllowMethods     string   `json:"allow_methods,omitempty"`
	AllowHeaders     string   `json:"allow_headers,omitempty"`
	Misconfigured    bool     `json:"misconfigured"`
	Issues           []string `json:"issues,omitempty"`
}

// LatencyInfo contains latency measurement results
type LatencyInfo struct {
	Host         string   `json:"host"`
	Samples      int      `json:"samples"`
	Min          string   `json:"min"`
	Max          string   `json:"max"`
	Average      string   `json:"average"`
	StdDev       string   `json:"std_dev"`
	Jitter       string   `json:"jitter"`
	Measurements []string `json:"measurements,omitempty"`
}

// SecurityTxtInfo contains parsed security.txt data
type SecurityTxtInfo struct {
	Found              bool     `json:"found"`
	Location           string   `json:"location,omitempty"`
	Contact            []string `json:"contact,omitempty"`
	Expires            string   `json:"expires,omitempty"`
	Expired            bool     `json:"expired"`
	Encryption         string   `json:"encryption,omitempty"`
	Acknowledgments    string   `json:"acknowledgments,omitempty"`
	PreferredLanguages string   `json:"preferred_languages,omitempty"`
	Canonical          string   `json:"canonical,omitempty"`
	Policy             string   `json:"policy,omitempty"`
	Hiring             string   `json:"hiring,omitempty"`
	Issues             []string `json:"issues,omitempty"`
}

// IPv6Info contains IPv6 support information
type IPv6Info struct {
	Host      string   `json:"host"`
	HasAAAA   bool     `json:"has_aaaa"`
	Addresses []string `json:"addresses,omitempty"`
	Reachable bool     `json:"reachable"`
}

// RedirectInfo contains redirect chain analysis
type RedirectInfo struct {
	HTTPChain    []RedirectHop `json:"http_chain,omitempty"`
	HTTPSChain   []RedirectHop `json:"https_chain,omitempty"`
	HTTPSUpgrade bool          `json:"https_upgrade"`
}

type RedirectHop struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

// BannerInfo contains server banner analysis
type BannerInfo struct {
	Server           string   `json:"server,omitempty"`
	XPoweredBy       string   `json:"x_powered_by,omitempty"`
	SSH              string   `json:"ssh,omitempty"`
	FTP              string   `json:"ftp,omitempty"`
	SMTP             string   `json:"smtp,omitempty"`
	VersionDisclosed bool     `json:"version_disclosed"`
	Versions         []string `json:"versions,omitempty"`
}

type AnalysisResult struct {
	Host            string
	Timestamp       string
	IP              []string
	DNS             DNSInfo
	TLS             TLSInfo
	SSLGrade        SSLGrade
	HTTP            HTTPInfo
	Content         ContentInfo
	EmailSecurity   EmailSecurityInfo
	Components      []SoftwareComponent
	Vulnerabilities []CVEResult
	Geo             []GeoInfo
	Ports           []PortInfo
	Performance     PerformanceInfo
	CDN             CDNInfo
	CloudProvider   CloudProviderInfo
	ServiceMesh     ServiceMeshInfo
	LoadBalancer    LoadBalancerInfo
	Container       ContainerInfo
	Network         NetworkInfo
	Findings        []Finding
	// New advanced analysis fields
	WHOIS       WHOISInfo       `json:"whois,omitempty"`
	Subdomains  SubdomainInfo   `json:"subdomains,omitempty"`
	DNSSEC      DNSSECInfo      `json:"dnssec,omitempty"`
	WAF         WAFInfo         `json:"waf,omitempty"`
	HTTPMethods HTTPMethodsInfo `json:"http_methods,omitempty"`
	CORS        CORSInfo        `json:"cors,omitempty"`
	Latency     LatencyInfo     `json:"latency,omitempty"`
	SecurityTxt SecurityTxtInfo `json:"security_txt,omitempty"`
	IPv6        IPv6Info        `json:"ipv6,omitempty"`
	Redirects   RedirectInfo    `json:"redirects,omitempty"`
	Banners     BannerInfo      `json:"banners,omitempty"`
}
