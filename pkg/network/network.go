package network

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	nethttp "net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mkaniukk/netanalytics/pkg/types"
)

// TraceRoute performs a traceroute to the specified host
func TraceRoute(host string, maxHops int) []types.HopInfo {
	return traceRoute(host, maxHops)
}

func traceRoute(host string, maxHops int) []types.HopInfo {
	var hops []types.HopInfo

	// Use system traceroute command for accurate hop-by-hop path
	cmd := exec.Command("traceroute", "-m", strconv.Itoa(maxHops), "-w", "1", "-q", "1", host)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Traceroute might not be available or requires elevated privileges
		return hops
	}

	// Parse traceroute output
	// Format: " 1  hostname (ip)  time1 ms  time2 ms  time3 ms"
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	ipRegex := regexp.MustCompile(`\(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)`)
	hopRegex := regexp.MustCompile(`^\s*(\d+)\s+(.+)`)
	timeRegex := regexp.MustCompile(`([0-9.]+)\s*ms`)

	for scanner.Scan() {
		line := scanner.Text()

		// Skip header line
		if strings.Contains(line, "traceroute to") {
			continue
		}

		// Match hop number
		hopMatch := hopRegex.FindStringSubmatch(line)
		if len(hopMatch) < 3 {
			continue
		}

		hopNum, _ := strconv.Atoi(hopMatch[1])
		rest := hopMatch[2]

		// Check for timeout
		if strings.Contains(rest, "* * *") {
			hops = append(hops, types.HopInfo{
				Hop:      hopNum,
				IP:       "*",
				Hostname: "Request timed out",
				RTT:      "-",
			})
			continue
		}

		// Extract IP
		ip := ""
		ipMatch := ipRegex.FindStringSubmatch(rest)
		if len(ipMatch) > 1 {
			ip = ipMatch[1]
		}

		// Extract hostname (before the IP in parentheses)
		hostname := ""
		if ipMatch != nil {
			parts := strings.Split(rest, "(")
			if len(parts) > 0 {
				hostname = strings.TrimSpace(parts[0])
			}
		}

		// Extract RTT (use first time value)
		rtt := ""
		timeMatch := timeRegex.FindStringSubmatch(rest)
		if len(timeMatch) > 1 {
			rtt = timeMatch[1] + " ms"
		}

		if ip != "" {
			hops = append(hops, types.HopInfo{
				Hop:      hopNum,
				IP:       ip,
				Hostname: hostname,
				RTT:      rtt,
			})
		}
	}

	return hops
}

func AnalyzeNetwork(host string, ips []string) types.NetworkInfo {
	info := types.NetworkInfo{}

	if len(ips) > 0 {
		ip := ips[0]
		if net.ParseIP(ip).To4() != nil {
			info.IPVersion = "IPv4"
		} else {
			info.IPVersion = "IPv6"
		}

		// Reverse DNS
		names, _ := net.LookupAddr(ip)
		if len(names) > 0 {
			info.ReverseDNS = names[0]
		}
	}

	return info
}

func GetGeolocation(ip string) types.GeoInfo {
	geo := types.GeoInfo{IP: ip}
	resp, err := nethttp.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=country,city,org,as,isp,hosting,proxy,mobile", ip))
	if err != nil {
		return geo
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return geo
	}

	if country, ok := result["country"].(string); ok {
		geo.Country = country
	}
	if city, ok := result["city"].(string); ok {
		geo.City = city
	}
	if org, ok := result["org"].(string); ok {
		geo.Organization = org
	}
	if asn, ok := result["as"].(string); ok {
		geo.ASN = asn
	}
	if isp, ok := result["isp"].(string); ok {
		geo.ISP = isp
	}
	if hosting, ok := result["hosting"].(string); ok {
		geo.Hosting = hosting
	}
	if proxy, ok := result["proxy"].(bool); ok {
		geo.Proxy = proxy
	}
	if mobile, ok := result["mobile"].(bool); ok {
		geo.Mobile = mobile
	}
	return geo
}

func ScanCommonPorts(host string) []types.PortInfo {
	commonPorts := map[int]string{
		80:   "HTTP",
		443:  "HTTPS",
		22:   "SSH",
		21:   "FTP",
		25:   "SMTP",
		3306: "MySQL",
		5432: "PostgreSQL",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
	}

	var results []types.PortInfo
	for port, service := range commonPorts {
		address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			conn.Close()
			results = append(results, types.PortInfo{
				Port:    port,
				Status:  "Open",
				Service: service,
			})
		}
	}
	return results
}

func AnalyzePerformance(host string) types.PerformanceInfo {
	perf := types.PerformanceInfo{}

	dnsStart := time.Now()
	addrs, err := net.LookupHost(host)
	if err == nil && len(addrs) > 0 {
		perf.DNSLookup = time.Since(dnsStart).String()

		tcpStart := time.Now()
		conn, err := net.DialTimeout("tcp", host+":443", 5*time.Second)
		if err == nil {
			perf.TCPConnect = time.Since(tcpStart).String()

			tlsStart := time.Now()
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true,
			})
			if err := tlsConn.Handshake(); err == nil {
				perf.TLSHandshake = time.Since(tlsStart).String()
				tlsConn.Close()
			} else {
				conn.Close()
			}
		}
	}

	totalStart := time.Now()
	resp, err := nethttp.Get("https://" + host)
	if err == nil {
		perf.FirstByte = time.Since(totalStart).String()
		resp.Body.Close()
	}
	perf.TotalTime = time.Since(totalStart).String()
	return perf
}
