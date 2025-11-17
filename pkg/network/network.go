package network

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	nethttp "net/http"
	"time"

	"netanalyze/pkg/types"
)

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
