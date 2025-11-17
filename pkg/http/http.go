package http

import (
	"fmt"
	nethttp "net/http"
	"strings"
	"time"

	"netanalyze/pkg/types"
)

func detectOS(headers nethttp.Header, server string) string {
	server = strings.ToLower(server)
	if strings.Contains(server, "win32") || strings.Contains(server, "win64") {
		return "Windows"
	}
	if strings.Contains(server, "ubuntu") {
		return "Ubuntu Linux"
	}
	if strings.Contains(server, "debian") {
		return "Debian Linux"
	}
	if strings.Contains(server, "centos") {
		return "CentOS Linux"
	}
	if strings.Contains(server, "red hat") || strings.Contains(server, "rhel") {
		return "Red Hat Linux"
	}
	if strings.Contains(server, "unix") || strings.Contains(server, "bsd") {
		return "Unix/BSD"
	}
	if strings.Contains(server, "microsoft-iis") {
		return "Windows (IIS)"
	}
	if strings.Contains(server, "apache") {
		return "Unix-like (Apache)"
	}
	if strings.Contains(server, "nginx") {
		return "Unix-like (Nginx)"
	}
	if xPoweredBy := headers.Get("X-Powered-By"); xPoweredBy != "" {
		xPoweredBy = strings.ToLower(xPoweredBy)
		if strings.Contains(xPoweredBy, "asp.net") {
			return "Windows (ASP.NET)"
		}
		if strings.Contains(xPoweredBy, "php") {
			return "Unix-like (PHP)"
		}
	}
	return "Unknown"
}

func detectTechnology(headers nethttp.Header) []string {
	var tech []string
	if server := headers.Get("Server"); server != "" {
		tech = append(tech, server)
	}
	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		tech = append(tech, poweredBy)
	}
	if aspVersion := headers.Get("X-AspNet-Version"); aspVersion != "" {
		tech = append(tech, "ASP.NET "+aspVersion)
	}
	if generator := headers.Get("X-Generator"); generator != "" {
		tech = append(tech, generator)
	}
	if headers.Get("CF-Ray") != "" {
		tech = append(tech, "Cloudflare CDN")
	}
	if headers.Get("X-Amz-Cf-Id") != "" {
		tech = append(tech, "AWS CloudFront")
	}
	if headers.Get("X-Azure-Ref") != "" {
		tech = append(tech, "Azure CDN")
	}
	if headers.Get("X-Cache") != "" {
		tech = append(tech, "Caching Layer")
	}
	return tech
}

func checkSecurityHeaders(headers nethttp.Header) map[string]string {
	secHeaders := make(map[string]string)
	importantHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"Referrer-Policy",
		"Permissions-Policy",
	}
	for _, header := range importantHeaders {
		if value := headers.Get(header); value != "" {
			secHeaders[header] = value
		} else {
			secHeaders[header] = "Not Set"
		}
	}
	return secHeaders
}

func detectTechStack(headers nethttp.Header, body string) types.TechFingerprint {
	tech := types.TechFingerprint{}
	if server := headers.Get("Server"); server != "" {
		tech.WebServer = server
	}

	if h2 := headers.Get("X-Firefox-Spdy"); h2 != "" || headers.Get("Alt-Svc") != "" {
		if strings.Contains(headers.Get("Alt-Svc"), "h3") {
			tech.HTTPVersion = "HTTP/3"
		} else {
			tech.HTTPVersion = "HTTP/2"
		}
	}

	if xPowered := headers.Get("X-Powered-By"); xPowered != "" {
		lower := strings.ToLower(xPowered)
		if strings.Contains(lower, "php") {
			tech.Language = append(tech.Language, xPowered)
		} else if strings.Contains(lower, "asp.net") {
			tech.Language = append(tech.Language, "ASP.NET")
			tech.Framework = append(tech.Framework, xPowered)
		}
	}

	if body != "" {
		body = strings.ToLower(body)
		if strings.Contains(body, "wp-content") || strings.Contains(body, "wordpress") {
			tech.CMS = "WordPress"
		} else if strings.Contains(body, "joomla") {
			tech.CMS = "Joomla"
		} else if strings.Contains(body, "drupal") {
			tech.CMS = "Drupal"
		} else if strings.Contains(body, "shopify") {
			tech.CMS = "Shopify"
		} else if strings.Contains(body, "wix.com") {
			tech.CMS = "Wix"
		}

		if strings.Contains(body, "google-analytics.com") || strings.Contains(body, "gtag") {
			tech.Analytics = append(tech.Analytics, "Google Analytics")
		}
		if strings.Contains(body, "googletagmanager.com") {
			tech.Analytics = append(tech.Analytics, "Google Tag Manager")
		}
		if strings.Contains(body, "facebook.com/tr") || strings.Contains(body, "fbq") {
			tech.Analytics = append(tech.Analytics, "Facebook Pixel")
		}

		if strings.Contains(body, "react") {
			tech.JavaScript = append(tech.JavaScript, "React")
		}
		if strings.Contains(body, "vue.js") || strings.Contains(body, "vuejs") {
			tech.JavaScript = append(tech.JavaScript, "Vue.js")
		}
		if strings.Contains(body, "angular") {
			tech.JavaScript = append(tech.JavaScript, "Angular")
		}
		if strings.Contains(body, "jquery") {
			tech.JavaScript = append(tech.JavaScript, "jQuery")
		}
	}
	return tech
}

func AnalyzeHTTP(url string) types.HTTPInfo {
	info := types.HTTPInfo{
		SecurityHeaders: make(map[string]string),
	}
	var redirects []string

	client := &nethttp.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *nethttp.Request, via []*nethttp.Request) error {
			redirects = append(redirects, req.URL.String())
			return nil
		},
	}

	start := time.Now()
	resp, err := client.Get(url)
	if err != nil {
		return info
	}
	defer resp.Body.Close()

	info.Status = resp.StatusCode
	info.Server = resp.Header.Get("Server")
	info.ContentType = resp.Header.Get("Content-Type")
	info.Encoding = resp.Header.Get("Content-Encoding")
	info.PoweredBy = resp.Header.Get("X-Powered-By")
	info.Headers = resp.Header
	info.RedirectChain = redirects
	info.ContentLength = resp.ContentLength
	info.Duration = time.Since(start).String()

	// Extract cookies
	for _, cookie := range resp.Cookies() {
		cookieInfo := cookie.Name
		if cookie.HttpOnly {
			cookieInfo += " (HttpOnly)"
		}
		if cookie.Secure {
			cookieInfo += " (Secure)"
		}
		if cookie.SameSite != nethttp.SameSiteDefaultMode {
			cookieInfo += fmt.Sprintf(" (SameSite=%v)", cookie.SameSite)
		}
		info.Cookies = append(info.Cookies, cookieInfo)
	}

	body := ""
	if resp.ContentLength < 50000 || resp.ContentLength == -1 {
		bodyBytes := make([]byte, 50000)
		n, _ := resp.Body.Read(bodyBytes)
		body = string(bodyBytes[:n])
	}

	info.OS = detectOS(resp.Header, info.Server)
	info.Technology = detectTechnology(resp.Header)
	info.SecurityHeaders = checkSecurityHeaders(resp.Header)
	info.TechStack = detectTechStack(resp.Header, body)
	return info
}
