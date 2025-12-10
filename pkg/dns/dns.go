package dns

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/mkaniukk/netanalytics/pkg/types"

	"github.com/miekg/dns"
)

func lookupSOA(host string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeSOA)
	c := new(dns.Client)
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return "", err
	}
	for _, ans := range r.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			return soa.Ns, nil
		}
	}
	return "", nil
}

func AnalyzeDNS(host string) types.DNSInfo {
	info := types.DNSInfo{}
	resolver := net.Resolver{}
	ctx := context.Background()
	start := time.Now()

	ips, _ := resolver.LookupHost(ctx, host)
	info.A = ips

	addrs, _ := resolver.LookupIPAddr(ctx, host)
	for _, addr := range addrs {
		if addr.IP.To4() == nil {
			info.AAAA = append(info.AAAA, addr.IP.String())
		}
	}

	cname, _ := resolver.LookupCNAME(ctx, host)
	if cname != "" {
		info.CNAME = []string{cname}
	}

	mxs, _ := resolver.LookupMX(ctx, host)
	for _, mx := range mxs {
		info.MX = append(info.MX, mx.Host)
	}

	nss, _ := resolver.LookupNS(ctx, host)
	for _, ns := range nss {
		info.NS = append(info.NS, ns.Host)
	}

	txts, _ := resolver.LookupTXT(ctx, host)
	info.TXT = txts

	soa, _ := lookupSOA(host)
	info.SOA = soa

	// Lookup CAA records (Certificate Authority Authorization)
	caaMsg := new(dns.Msg)
	caaMsg.SetQuestion(dns.Fqdn(host), dns.TypeCAA)
	caaClient := new(dns.Client)
	caaResp, _, _ := caaClient.Exchange(caaMsg, "8.8.8.8:53")
	if caaResp != nil {
		for _, ans := range caaResp.Answer {
			if caa, ok := ans.(*dns.CAA); ok {
				info.CAA = append(info.CAA, caa.Tag+": "+caa.Value)
			}
		}
	}

	for _, ip := range info.A {
		names, _ := resolver.LookupAddr(ctx, ip)
		info.Reverse = append(info.Reverse, names...)
	}

	info.Duration = time.Since(start).String()
	return info
}

func AnalyzeEmailSecurity(host string) types.EmailSecurityInfo {
	info := types.EmailSecurityInfo{}

	// Check SPF
	txts, _ := net.LookupTXT(host)
	for _, txt := range txts {
		if len(txt) > 0 && (txt[0:6] == "v=spf1" || txt == "v=spf1") {
			info.SPF = true
			info.SPFRecord = txt
			break
		}
		// Handle case where SPF might be split across multiple strings in a single TXT record?
		// net.LookupTXT returns []string, where each string is a record.
		// Actually, SPF records start with v=spf1.
		if len(txt) >= 6 && txt[0:6] == "v=spf1" {
			info.SPF = true
			info.SPFRecord = txt
			break
		}
	}

	// Check DMARC
	dmarcHost := "_dmarc." + host
	dmarcTxts, _ := net.LookupTXT(dmarcHost)
	for _, txt := range dmarcTxts {
		if len(txt) >= 8 && txt[0:8] == "v=DMARC1" {
			info.DMARC = true
			info.DMARCRecord = txt

			// Parse policy
			parts := strings.Split(txt, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "p=") {
					info.DMARCPolicy = strings.TrimPrefix(part, "p=")
					break
				}
			}
			break
		}
	}

	return info
}
