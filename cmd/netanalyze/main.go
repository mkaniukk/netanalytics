package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/mkaniukk/netanalytics/pkg/analyzer"
	"github.com/mkaniukk/netanalytics/pkg/content"
	"github.com/mkaniukk/netanalytics/pkg/detection"
	"github.com/mkaniukk/netanalytics/pkg/dns"
	"github.com/mkaniukk/netanalytics/pkg/http"
	"github.com/mkaniukk/netanalytics/pkg/network"
	"github.com/mkaniukk/netanalytics/pkg/output"
	"github.com/mkaniukk/netanalytics/pkg/tls"
	"github.com/mkaniukk/netanalytics/pkg/types"
	"github.com/mkaniukk/netanalytics/pkg/vuln"
)

func main() {
	jsonOut := flag.Bool("json", false, "Output JSON instead of pretty text")
	enableGeo := flag.Bool("geo", false, "Show geolocation information")
	enablePorts := flag.Bool("ports", false, "Scan common ports")
	enablePerf := flag.Bool("perf", false, "Show performance metrics")
	enableTrace := flag.Bool("trace", false, "Show network hops (traceroute)")
	enableCVE := flag.Bool("cve", false, "Attempt CVE lookups for detected technologies (uses NVD API)")
	verbose := flag.Bool("verbose", false, "Show all details including non-detected items")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Println("Usage: netanalyze [--json] [--geo] [--ports] [--perf] [--trace] [--verbose] <host>")
		fmt.Println("\nOptions:")
		fmt.Println("  --json         Output in JSON format")
		fmt.Println("  --geo          Show geolocation information")
		fmt.Println("  --ports        Scan common ports")
		fmt.Println("  --perf         Show performance metrics")
		fmt.Println("  --trace        Show network hops (traceroute)")
		fmt.Println("  --verbose      Show all details including non-detected items")
		fmt.Println("  --cve          Attempt to find related CVEs (experimental)")
		os.Exit(1)
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

	// Analyze findings
	result.Findings = analyzer.AnalyzeFindings(&result)

	if *jsonOut {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		output.PrintReport(result, *verbose)
	}
}
