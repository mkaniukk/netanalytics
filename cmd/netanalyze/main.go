package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mkaniukk/netanalytics/pkg/advanced"
	"github.com/mkaniukk/netanalytics/pkg/analyzer"
	"github.com/mkaniukk/netanalytics/pkg/content"
	"github.com/mkaniukk/netanalytics/pkg/detection"
	"github.com/mkaniukk/netanalytics/pkg/dns"
	"github.com/mkaniukk/netanalytics/pkg/http"
	"github.com/mkaniukk/netanalytics/pkg/network"
	"github.com/mkaniukk/netanalytics/pkg/output"
	"github.com/mkaniukk/netanalytics/pkg/subdomain"
	"github.com/mkaniukk/netanalytics/pkg/tls"
	"github.com/mkaniukk/netanalytics/pkg/types"
	"github.com/mkaniukk/netanalytics/pkg/vuln"
	"github.com/mkaniukk/netanalytics/pkg/whois"
)

func main() {
	jsonOut := flag.Bool("json", false, "Output JSON instead of pretty text")
	enableGeo := flag.Bool("geo", false, "Show geolocation information")
	enablePorts := flag.Bool("ports", false, "Scan common ports")
	enablePerf := flag.Bool("perf", false, "Show performance metrics")
	enableTrace := flag.Bool("trace", false, "Show network hops (traceroute)")
	enableCVE := flag.Bool("cve", false, "Attempt CVE lookups for detected technologies (uses NVD API)")
	verbose := flag.Bool("verbose", false, "Show all details including non-detected items")
	// New flags for advanced features
	enableWHOIS := flag.Bool("whois", false, "Show WHOIS domain registration information")
	enableSubdomains := flag.Bool("subdomains", false, "Enumerate subdomains via certificate transparency")
	enableDNSSEC := flag.Bool("dnssec", false, "Check DNSSEC configuration")
	enableWAF := flag.Bool("waf", false, "Detect Web Application Firewalls")
	enableMethods := flag.Bool("methods", false, "Test allowed HTTP methods")
	enableCORS := flag.Bool("cors", false, "Check CORS configuration")
	enableLatency := flag.Bool("latency", false, "Measure response latency (10 samples)")
	enableSecurityTxt := flag.Bool("sectxt", false, "Parse and analyze security.txt")
	enableIPv6 := flag.Bool("ipv6", false, "Check IPv6 support and reachability")
	enableRedirects := flag.Bool("redirects", false, "Analyze redirect chains")
	enableBanners := flag.Bool("banners", false, "Collect service banners (SSH, FTP, SMTP)")
	enableAll := flag.Bool("all", false, "Enable all analysis features")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Println("Usage: netanalyze [options] <host>")
		fmt.Println("\nBasic Options:")
		fmt.Println("  --json         Output in JSON format")
		fmt.Println("  --geo          Show geolocation information")
		fmt.Println("  --ports        Scan common ports")
		fmt.Println("  --perf         Show performance metrics")
		fmt.Println("  --trace        Show network hops (traceroute)")
		fmt.Println("  --verbose      Show all details including non-detected items")
		fmt.Println("  --cve          Attempt to find related CVEs (experimental)")
		fmt.Println("\nAdvanced Options:")
		fmt.Println("  --whois        Show WHOIS domain registration information")
		fmt.Println("  --subdomains   Enumerate subdomains via certificate transparency")
		fmt.Println("  --dnssec       Check DNSSEC configuration")
		fmt.Println("  --waf          Detect Web Application Firewalls")
		fmt.Println("  --methods      Test allowed HTTP methods")
		fmt.Println("  --cors         Check CORS configuration")
		fmt.Println("  --latency      Measure response latency (10 samples)")
		fmt.Println("  --sectxt       Parse and analyze security.txt")
		fmt.Println("  --ipv6         Check IPv6 support and reachability")
		fmt.Println("  --redirects    Analyze redirect chains")
		fmt.Println("  --banners      Collect service banners (SSH, FTP, SMTP)")
		fmt.Println("  --all          Enable all analysis features")
		os.Exit(1)
	}

	// Enable all features if --all flag is set
	if *enableAll {
		*enableGeo = true
		*enablePorts = true
		*enablePerf = true
		*enableCVE = true
		*enableWHOIS = true
		*enableSubdomains = true
		*enableDNSSEC = true
		*enableWAF = true
		*enableMethods = true
		*enableCORS = true
		*enableLatency = true
		*enableSecurityTxt = true
		*enableIPv6 = true
		*enableRedirects = true
		*enableBanners = true
	}

	host := flag.Args()[0]
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")

	result := types.AnalysisResult{
		Host:      host,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	result.DNS = dns.AnalyzeDNS(host)
	result.IP = result.DNS.A
	result.Network = network.AnalyzeNetwork(host, result.IP)
	result.EmailSecurity = dns.AnalyzeEmailSecurity(host)

	result.TLS = tls.AnalyzeTLS(host)
	if result.TLS.Version != "" {
		result.SSLGrade = tls.GradeSSL(result.TLS)
	}

	result.HTTP = http.AnalyzeHTTP("https://" + host)
	result.Content = content.AnalyzeContent(host, "https")
	result.CDN = detection.DetectCDN(result.HTTP.Headers)
	result.ServiceMesh = detection.DetectServiceMesh(result.HTTP.Headers)
	result.LoadBalancer = detection.DetectLoadBalancer(result.HTTP.Headers)
	result.Container = detection.DetectContainerEnvironment(result.HTTP.Headers, result.DNS)
	result.Components = vuln.IdentifyComponents(result.HTTP, result.TLS)
	if *enableCVE {
		result.Vulnerabilities = vuln.LookupCVEs(result.Components)
	}

	if *enableGeo && len(result.IP) > 0 {
		for _, ip := range result.IP {
			if net.ParseIP(ip).To4() != nil {
				result.Geo = append(result.Geo, network.GetGeolocation(ip))
			}
		}
		result.CloudProvider = detection.DetectCloudProvider(result.HTTP.Headers, result.Geo)
	}

	if *enablePorts {
		result.Ports = network.ScanCommonPorts(host)
	}

	if *enablePerf {
		result.Performance = network.AnalyzePerformance(host)
	}

	if *enableTrace {
		result.Network.Hops = network.TraceRoute(host, 30)
		result.Network.HopCount = len(result.Network.Hops)
	}

	// Advanced analysis features
	if *enableWHOIS {
		result.WHOIS = whois.LookupWHOIS(host)
	}

	if *enableSubdomains {
		result.Subdomains = subdomain.EnumerateSubdomains(host)
	}

	if *enableDNSSEC {
		result.DNSSEC = advanced.CheckDNSSEC(host)
	}

	if *enableWAF {
		result.WAF = advanced.DetectWAF(host)
	}

	if *enableMethods {
		result.HTTPMethods = advanced.TestHTTPMethods(host)
	}

	if *enableCORS {
		result.CORS = advanced.CheckCORS(host)
	}

	if *enableLatency {
		result.Latency = advanced.MeasureLatency(host, 10)
	}

	if *enableSecurityTxt {
		result.SecurityTxt = advanced.ParseSecurityTxt(host)
	}

	if *enableIPv6 {
		result.IPv6 = advanced.CheckIPv6Support(host)
	}

	if *enableRedirects {
		result.Redirects = advanced.CheckRedirects(host)
	}

	if *enableBanners {
		result.Banners = advanced.AnalyzeServerBanner(host)
	}

	// Analyze findings
	result.Findings = analyzer.AnalyzeFindings(&result)

	if *jsonOut {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		output.PrintReport(result, *verbose)
	}
}
