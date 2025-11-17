package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"netanalyze/pkg/detection"
	"netanalyze/pkg/dns"
	"netanalyze/pkg/http"
	"netanalyze/pkg/network"
	"netanalyze/pkg/output"
	"netanalyze/pkg/tls"
	"netanalyze/pkg/types"
)

func main() {
	jsonOut := flag.Bool("json", false, "Output JSON instead of pretty text")
	enableGeo := flag.Bool("geo", false, "Show geolocation information")
	enablePorts := flag.Bool("ports", false, "Scan common ports")
	enablePerf := flag.Bool("perf", false, "Show performance metrics")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Println("Usage: netanalyze [--json] [--geo] [--ports] [--perf] <host>")
		fmt.Println("\nOptions:")
		fmt.Println("  --json         Output in JSON format")
		fmt.Println("  --geo          Show geolocation information")
		fmt.Println("  --ports        Scan common ports")
		fmt.Println("  --perf         Show performance metrics")
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

	result.TLS = tls.AnalyzeTLS(host)
	if result.TLS.Version != "" {
		result.SSLGrade = tls.GradeSSL(result.TLS)
	}

	result.HTTP = http.AnalyzeHTTP("https://" + host)
	result.CDN = detection.DetectCDN(result.HTTP.Headers)
	result.ServiceMesh = detection.DetectServiceMesh(result.HTTP.Headers)
	result.LoadBalancer = detection.DetectLoadBalancer(result.HTTP.Headers)
	result.Container = detection.DetectContainerEnvironment(result.HTTP.Headers, result.DNS)

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

	if *jsonOut {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))
	} else {
		output.PrintReport(result)
	}
}
