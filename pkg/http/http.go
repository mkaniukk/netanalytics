package http

import (
	"fmt"
	nethttp "net/http"
	"regexp"
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
	if mvcVersion := headers.Get("X-AspNetMvc-Version"); mvcVersion != "" {
		tech = append(tech, "ASP.NET MVC "+mvcVersion)
	}
	if generator := headers.Get("X-Generator"); generator != "" {
		tech = append(tech, generator)
	}
	if runtime := headers.Get("X-Runtime"); runtime != "" {
		tech = append(tech, "Runtime: "+runtime)
	}
	if version := headers.Get("X-Version"); version != "" {
		tech = append(tech, "Version: "+version)
	}
	if drupal := headers.Get("X-Drupal-Cache"); drupal != "" {
		tech = append(tech, "Drupal")
	}
	if headers.Get("X-Drupal-Dynamic-Cache") != "" {
		tech = append(tech, "Drupal 8+")
	}
	if headers.Get("CF-Ray") != "" {
		cfVersion := headers.Get("CF-Cache-Status")
		if cfVersion != "" {
			tech = append(tech, "Cloudflare CDN")
		} else {
			tech = append(tech, "Cloudflare CDN")
		}
	}
	if headers.Get("X-Amz-Cf-Id") != "" {
		tech = append(tech, "AWS CloudFront")
	}
	if headers.Get("X-Azure-Ref") != "" {
		tech = append(tech, "Azure CDN")
	}
	if headers.Get("X-Varnish") != "" {
		tech = append(tech, "Varnish Cache")
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

func detectPlugins(body string) []string {
	var plugins []string
	// Regex to find plugins in wp-content/plugins/
	// Matches: wp-content/plugins/plugin-name/
	// Also tries to capture version if present in query string: ?ver=1.2.3
	pluginRegex := regexp.MustCompile(`wp-content/plugins/([a-zA-Z0-9\-_]+)(?:[^"']*?[?&]ver=([\d.]+))?`)

	matches := pluginRegex.FindAllStringSubmatch(body, -1)
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) > 1 {
			name := match[1]
			version := ""
			if len(match) > 2 {
				version = match[2]
			}

			fullName := name
			if version != "" {
				fullName = name + " " + version
			}

			if !seen[fullName] {
				plugins = append(plugins, fullName)
				seen[fullName] = true
			}
		}
	}
	return plugins
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

		// JavaScript frameworks with version detection
		if reactMatch := regexp.MustCompile(`react["']?[:\s,]+["']?(\d+\.\d+[.\d]*)`).FindStringSubmatch(body); len(reactMatch) > 1 {
			tech.JavaScript = append(tech.JavaScript, "React "+reactMatch[1])
		} else if strings.Contains(body, "react") {
			tech.JavaScript = append(tech.JavaScript, "React")
		}

		if vueMatch := regexp.MustCompile(`vue["']?[:\s,]+["']?(\d+\.\d+[.\d]*)`).FindStringSubmatch(body); len(vueMatch) > 1 {
			tech.JavaScript = append(tech.JavaScript, "Vue.js "+vueMatch[1])
		} else if strings.Contains(body, "vue.js") || strings.Contains(body, "vuejs") {
			tech.JavaScript = append(tech.JavaScript, "Vue.js")
		}

		if angularMatch := regexp.MustCompile(`angular["']?[:\s,]+["']?(\d+\.\d+[.\d]*)`).FindStringSubmatch(body); len(angularMatch) > 1 {
			tech.JavaScript = append(tech.JavaScript, "Angular "+angularMatch[1])
		} else if strings.Contains(body, "angular") {
			tech.JavaScript = append(tech.JavaScript, "Angular")
		}

		if jqueryMatch := regexp.MustCompile(`jquery[\s-]*(v?\d+\.\d+[.\d]*)`).FindStringSubmatch(strings.ToLower(body)); len(jqueryMatch) > 1 {
			tech.JavaScript = append(tech.JavaScript, "jQuery "+strings.TrimPrefix(jqueryMatch[1], "v"))
		} else if strings.Contains(body, "jquery") {
			tech.JavaScript = append(tech.JavaScript, "jQuery")
		}

		// CMS detection
		if strings.Contains(body, "wp-content") || strings.Contains(body, "wordpress") {
			if wpMatch := regexp.MustCompile(`wordpress[\s/]*(\d+\.\d+[.\d]*)`).FindStringSubmatch(strings.ToLower(body)); len(wpMatch) > 1 {
				tech.CMS = "WordPress " + wpMatch[1]
			} else if metaGen := regexp.MustCompile(`<meta[^>]+generator[^>]+WordPress[\s]+(\d+\.\d+[.\d]*)`).FindStringSubmatch(body); len(metaGen) > 1 {
				tech.CMS = "WordPress " + metaGen[1]
			} else {
				tech.CMS = "WordPress"
			}
		}

		if strings.Contains(body, "Joomla") && tech.CMS == "" {
			if joomlaMatch := regexp.MustCompile(`Joomla[!\s]*(\d+\.\d+[.\d]*)`).FindStringSubmatch(body); len(joomlaMatch) > 1 {
				tech.CMS = "Joomla " + joomlaMatch[1]
			} else {
				tech.CMS = "Joomla"
			}
		}

		if strings.Contains(body, "Drupal") && tech.CMS == "" {
			if drupalMatch := regexp.MustCompile(`Drupal[\s]*(\d+\.\d+[.\d]*)`).FindStringSubmatch(body); len(drupalMatch) > 1 {
				tech.CMS = "Drupal " + drupalMatch[1]
			} else {
				tech.CMS = "Drupal"
			}
		}

		tech.Plugins = detectPlugins(body)
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
