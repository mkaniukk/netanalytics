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
	Version       string
	CipherSuite   string
	Subject       string
	Issuer        string
	Expiry        string
	KeyType       string
	SignatureAlgo string
	SAN           []string
	SerialNumber  string
	ChainLength   int
	OCSPStapling  bool
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

type NetworkInfo struct {
	ASN         string
	ASNOrg      string
	IPVersion   string
	ReverseDNS  string
	HopCount    int
}

type AnalysisResult struct {
	Host           string
	Timestamp      string
	IP             []string
	DNS            DNSInfo
	TLS            TLSInfo
	SSLGrade       SSLGrade
	HTTP           HTTPInfo
	Geo            []GeoInfo
	Ports          []PortInfo
	Performance    PerformanceInfo
	CDN            CDNInfo
	CloudProvider  CloudProviderInfo
	ServiceMesh    ServiceMeshInfo
	LoadBalancer   LoadBalancerInfo
	Container      ContainerInfo
	WHOIS          WHOISInfo
	Network        NetworkInfo
}
