package content

import (
	"io"
	"net/http"
	"time"

	"github.com/mkaniukk/netanalytics/pkg/types"
)

func fetchResourceMetadata(client *http.Client, url string) (bool, int64) {
	resp, err := client.Head(url)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if resp.ContentLength >= 0 {
				return true, resp.ContentLength
			}
			// Need to fall back to GET to determine size
		} else if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return false, 0
		}
	}

	resp, err = client.Get(url)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, 0
	}
	size, _ := io.Copy(io.Discard, resp.Body)
	return true, size
}

func AnalyzeContent(host string, protocol string) types.ContentInfo {
	info := types.ContentInfo{}

	// Determine base URL
	baseURL := "https://" + host
	if protocol == "http" {
		baseURL = "http://" + host
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// Check robots.txt
	if found, size := fetchResourceMetadata(client, baseURL+"/robots.txt"); found {
		info.RobotsTxt = true
		info.RobotsSize = size
	}

	// Check sitemap.xml
	if found, size := fetchResourceMetadata(client, baseURL+"/sitemap.xml"); found {
		info.SitemapXml = true
		info.SitemapSize = size
	}

	// Check security.txt (standard locations)
	locations := []string{
		"/.well-known/security.txt",
		"/security.txt",
	}

	for _, loc := range locations {
		if found, size := fetchResourceMetadata(client, baseURL+loc); found {
			info.SecurityTxt = true
			info.SecuritySize = size
			break
		}
	}

	// Check for exposed sensitive files
	exposedFiles := []string{
		"/.htaccess",
		"/.htpasswd",
		"/.env",
		"/nginx.conf",
		"/web.config",
		"/server-status",
		"/nginx_status",
		"/.git/HEAD",
		"/phpinfo.php",
		"/info.php",
		"/.DS_Store",
		"/.svn/HEAD",
		"/Dockerfile",
		"/docker-compose.yml",
		"/package.json",
		"/composer.json",
		"/Gemfile",
		"/requirements.txt",
		"/wp-config.php.bak",
		"/config.php.bak",
		"/README.md",
		"/LICENSE",
		"/CHANGELOG.md",
		"/error.log",
		"/debug.log",
	}

	for _, file := range exposedFiles {
		if found, _ := fetchResourceMetadata(client, baseURL+file); found {
			info.ExposedFiles = append(info.ExposedFiles, file)
		}
	}

	return info
}
