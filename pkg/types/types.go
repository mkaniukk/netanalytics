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
	Registrar    string
	CreationDate string
	ExpiryDate   string
	NameServers  []string
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
	RobotsTxt    bool  `json:"robots_txt"`
	SitemapXml   bool  `json:"sitemap_xml"`
	SecurityTxt  bool  `json:"security_txt"`
	RobotsSize   int64 `json:"robots_size"`
	SitemapSize  int64 `json:"sitemap_size"`
	SecuritySize int64 `json:"security_size"`
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
}
