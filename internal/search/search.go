package search

import (
	"fmt"
	"strings"
)

// SearchURLs generates search URLs for various security databases
type SearchURLs struct {
	IP string
}

// NewSearchURLs creates a new SearchURLs instance
func NewSearchURLs(ip string) *SearchURLs {
	return &SearchURLs{IP: ip}
}

// GetShodanURL returns the Shodan search URL for the IP
func (s *SearchURLs) GetShodanURL() string {
	return fmt.Sprintf("https://www.shodan.io/search?query=%s", s.IP)
}

// GetCensysURL returns the Censys search URL for the IP
func (s *SearchURLs) GetCensysURL() string {
	return fmt.Sprintf("https://search.censys.io/hosts/%s", s.IP)
}

// GetZoomeyeURL returns the Zoomeye search URL for the IP
func (s *SearchURLs) GetZoomeyeURL() string {
	return fmt.Sprintf("https://www.zoomeye.org/searchResult?q=%s", s.IP)
}

// GetGoogleDorkURLs returns Google dork URLs for camera-specific searches
func (s *SearchURLs) GetGoogleDorkURLs() []string {
	queries := []string{
		fmt.Sprintf("site:%s inurl:view/view.shtml", s.IP),
		fmt.Sprintf("site:%s inurl:admin.html", s.IP),
		fmt.Sprintf("site:%s inurl:login", s.IP),
		fmt.Sprintf("intitle:'webcam' inurl:%s", s.IP),
		fmt.Sprintf("site:%s inurl:cgi-bin", s.IP),
		fmt.Sprintf("site:%s inurl:snapshot", s.IP),
		fmt.Sprintf("site:%s inurl:stream", s.IP),
		fmt.Sprintf("site:%s inurl:video", s.IP),
		fmt.Sprintf("site:%s inurl:live", s.IP),
		fmt.Sprintf("site:%s inurl:camera", s.IP),
	}

	var urls []string
	for _, query := range queries {
		urls = append(urls, fmt.Sprintf("https://www.google.com/search?q=%s", strings.ReplaceAll(query, " ", "+")))
	}
	return urls
}

// FormatSearchURLs formats all search URLs for display
func (s *SearchURLs) FormatSearchURLs() string {
	result := "Search URLs for manual verification:\n"
	result += fmt.Sprintf("  🔹 Shodan: %s\n", s.GetShodanURL())
	result += fmt.Sprintf("  🔹 Censys: %s\n", s.GetCensysURL())
	result += fmt.Sprintf("  🔹 Zoomeye: %s\n", s.GetZoomeyeURL())

	result += "\nGoogle Dorking Suggestions:\n"
	for i, url := range s.GetGoogleDorkURLs() {
		if i >= 5 { // Limit to first 5 dorks for brevity
			result += "  ... and more\n"
			break
		}
		query := strings.Split(url, "q=")[1]
		result += fmt.Sprintf("  🔍 %s\n", query)
	}

	return result
}

// GetCameraSpecificDorks returns camera-specific Google dorks
func GetCameraSpecificDorks(ip string) []string {
	return []string{
		fmt.Sprintf("site:%s inurl:view/view.shtml", ip),
		fmt.Sprintf("site:%s inurl:admin.html", ip),
		fmt.Sprintf("site:%s inurl:login", ip),
		fmt.Sprintf("intitle:'webcam' inurl:%s", ip),
		fmt.Sprintf("site:%s inurl:cgi-bin", ip),
		fmt.Sprintf("site:%s inurl:snapshot", ip),
		fmt.Sprintf("site:%s inurl:stream", ip),
		fmt.Sprintf("site:%s inurl:video", ip),
		fmt.Sprintf("site:%s inurl:live", ip),
		fmt.Sprintf("site:%s inurl:camera", ip),
		fmt.Sprintf("site:%s inurl:mjpg", ip),
		fmt.Sprintf("site:%s inurl:mjpeg", ip),
		fmt.Sprintf("site:%s inurl:onvif", ip),
		fmt.Sprintf("site:%s inurl:rtsp", ip),
		fmt.Sprintf("site:%s inurl:rtmp", ip),
	}
}
