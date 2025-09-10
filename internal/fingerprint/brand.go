package fingerprint

import (
	"regexp"
	"strings"

	"github.com/postfix/cctvscan/internal/cvedb"
)

// Brand keyword lists
var brandKeysHikvision = []string{"hikvision", "dvr", "nvr", "hik-connect", "ivms", "web service"}
var brandKeysDahua = []string{"dahua", "dvr", "nvr", "dss", "smartpss", "dmss"}
var brandKeysAxis = []string{"axis", "axis communications", "axis camera", "axis mjpg"}
var brandKeysSony = []string{"sony", "ipela", "snc", "sony network camera"}
var brandKeysBosch = []string{"bosch", "security systems", "flexidome", "dinion", "autodome"}
var brandKeysSamsung = []string{"samsung", "samsung techwin", "samsung sds", "hanwha", "wisenet"}
var brandKeysPanasonic = []string{"panasonic", "network camera", "wv", "bb", "blc"}
var brandKeysVivotek = []string{"vivotek", "network camera", "ip camera", "fd", "sd"}
var brandKeysGeneric = []string{"camera", "webcam", "surveillance", "ip camera", "network camera", "dvr", "nvr", "recorder"}

// Version detection patterns for different brands
var versionPatterns = map[string]*regexp.Regexp{
	"Hikvision": regexp.MustCompile(`(?i)(?:hikvision|hik-connect|ivms).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
	"Dahua":     regexp.MustCompile(`(?i)(?:dahua|dss|smartpss).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
	"Axis":      regexp.MustCompile(`(?i)(?:axis|axis communications).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
	"Sony":      regexp.MustCompile(`(?i)(?:sony|ipela).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
	"Bosch":     regexp.MustCompile(`(?i)(?:bosch|flexidome|dinion).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
	"Samsung":   regexp.MustCompile(`(?i)(?:samsung|hanwha|wisenet).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
	"Panasonic": regexp.MustCompile(`(?i)(?:panasonic|wv|bb|blc).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
	"Vivotek":   regexp.MustCompile(`(?i)(?:vivotek|fd|sd).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
}

// Web page content patterns for brand detection
var webContentPatterns = map[string]*regexp.Regexp{
	"Hikvision": regexp.MustCompile(`(?i)(?:hikvision|hik-connect|ivms|web service|login\.jsp|main\.jsp)`),
	"Dahua":     regexp.MustCompile(`(?i)(?:dahua|dss|smartpss|dmss|login\.html|main\.html)`),
	"Axis":      regexp.MustCompile(`(?i)(?:axis|axis communications|axis camera|axis mjpg|axis-cgi)`),
	"Sony":      regexp.MustCompile(`(?i)(?:sony|ipela|snc|sony network camera)`),
	"Bosch":     regexp.MustCompile(`(?i)(?:bosch|flexidome|dinion|autodome|security systems)`),
	"Samsung":   regexp.MustCompile(`(?i)(?:samsung|hanwha|wisenet|samsung techwin)`),
	"Panasonic": regexp.MustCompile(`(?i)(?:panasonic|wv|bb|blc|network camera)`),
	"Vivotek":   regexp.MustCompile(`(?i)(?:vivotek|fd|sd|ip camera|network camera)`),
	"CP Plus":   regexp.MustCompile(`(?i)(?:cp plus|cpplus|cp-plus|cp_plus)`),
}

// Title patterns for brand detection
var titlePatterns = map[string]*regexp.Regexp{
	"Hikvision": regexp.MustCompile(`(?i)<title>.*?(?:hikvision|hik-connect|ivms).*?</title>`),
	"Dahua":     regexp.MustCompile(`(?i)<title>.*?(?:dahua|dss|smartpss).*?</title>`),
	"Axis":      regexp.MustCompile(`(?i)<title>.*?(?:axis|axis communications).*?</title>`),
	"Sony":      regexp.MustCompile(`(?i)<title>.*?(?:sony|ipela).*?</title>`),
	"Bosch":     regexp.MustCompile(`(?i)<title>.*?(?:bosch|flexidome).*?</title>`),
	"Samsung":   regexp.MustCompile(`(?i)<title>.*?(?:samsung|hanwha|wisenet).*?</title>`),
	"Panasonic": regexp.MustCompile(`(?i)<title>.*?(?:panasonic|wv|bb).*?</title>`),
	"Vivotek":   regexp.MustCompile(`(?i)<title>.*?(?:vivotek|fd|sd).*?</title>`),
}

// DetectResult contains brand detection results with version information
type DetectResult struct {
	Brand   string
	Note    string
	Version string
}

// Detect performs enhanced brand detection with version enumeration
func Detect(serverHdr, body, rtspServer string) (brand, note string) {
	result := DetectWithVersion(serverHdr, body, rtspServer)
	return result.Brand, result.Note
}

// DetectWithVersion performs brand detection and returns version information
func DetectWithVersion(serverHdr, body, rtspServer string) DetectResult {
	lh := strings.ToLower(serverHdr)
	lb := strings.ToLower(body)
	lr := strings.ToLower(rtspServer)

	// Enhanced brand detection with multiple methods
	brands := []string{"Hikvision", "Dahua", "Axis", "Sony", "Bosch", "Samsung", "Panasonic", "Vivotek", "CP Plus"}

	for _, brand := range brands {
		// Method 1: Header matching
		if headerContainsAny(lh, getBrandKeys(brand)) {
			version := extractVersion(body, brand)
			note := ""
			if version != "" {
				note = "Version: " + version
			}
			return DetectResult{Brand: brand, Note: note, Version: version}
		}

		// Method 2: Web content pattern matching
		if webContentPatterns[brand] != nil && webContentPatterns[brand].MatchString(body) {
			version := extractVersion(body, brand)
			note := "Web content match"
			if version != "" {
				note += " | Version: " + version
			}
			return DetectResult{Brand: brand, Note: note, Version: version}
		}

		// Method 3: Title pattern matching
		if titlePatterns[brand] != nil && titlePatterns[brand].MatchString(body) {
			version := extractVersion(body, brand)
			note := "Title match"
			if version != "" {
				note += " | Version: " + version
			}
			return DetectResult{Brand: brand, Note: note, Version: version}
		}

		// Method 4: Body keyword matching
		if headerContainsAny(lb, getBrandKeys(brand)) {
			version := extractVersion(body, brand)
			note := ""
			if version != "" {
				note = "Version: " + version
			}
			return DetectResult{Brand: brand, Note: note, Version: version}
		}

		// Method 5: RTSP server matching
		if strings.Contains(lr, strings.ToLower(brand)) {
			version := extractVersion(rtspServer, brand)
			note := "RTSP server: " + rtspServer
			if version != "" {
				note += " | Version: " + version
			}
			return DetectResult{Brand: brand, Note: note, Version: version}
		}
	}

	// RTSP server brand detection (fallback)
	if rtspServer != "" {
		if norm := normalizeRtspBrandFromServer(rtspServer); norm != "RTSP" && norm != "" {
			version := extractVersion(rtspServer, norm)
			note := "RTSP server: " + rtspServer
			if version != "" {
				note += " | Version: " + version
			}
			return DetectResult{Brand: norm, Note: note, Version: version}
		}
	}

	// Generic camera hints
	if headerContainsAny(lh, brandKeysGeneric) || headerContainsAny(lb, brandKeysGeneric) || headerContainsAny(lr, brandKeysGeneric) {
		return DetectResult{Brand: "Unknown cam", Note: "", Version: ""}
	}

	return DetectResult{Brand: "", Note: "", Version: ""}
}

// extractVersion extracts version information from content for a specific brand
func extractVersion(content, brand string) string {
	if pattern, exists := versionPatterns[brand]; exists {
		matches := pattern.FindStringSubmatch(content)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

// getBrandKeys returns the keyword list for a specific brand
func getBrandKeys(brand string) []string {
	switch brand {
	case "Hikvision":
		return brandKeysHikvision
	case "Dahua":
		return brandKeysDahua
	case "Axis":
		return brandKeysAxis
	case "Sony":
		return brandKeysSony
	case "Bosch":
		return brandKeysBosch
	case "Samsung":
		return brandKeysSamsung
	case "Panasonic":
		return brandKeysPanasonic
	case "Vivotek":
		return brandKeysVivotek
	case "CP Plus":
		return []string{"cp plus", "cpplus", "cp-plus", "cp_plus"}
	default:
		return []string{}
	}
}

func headerContainsAny(hdr string, keys []string) bool {
	h := strings.ToLower(hdr)
	for _, kw := range keys {
		if strings.Contains(h, kw) {
			return true
		}
	}
	return false
}

func normalizeRtspBrandFromServer(srvRaw string) string {
	s := strings.TrimSpace(srvRaw)
	low := strings.ToLower(s)

	if strings.Contains(low, "hipcam") {
		return "Hipcam"
	}
	if strings.Contains(low, "tvt") {
		return "TVT"
	}
	if strings.Contains(low, "ubnt") || strings.Contains(low, "ubiquiti") {
		return "Ubiquiti"
	}
	if strings.Contains(low, "gstreamer") {
		return "GStreamer"
	}
	if strings.Contains(low, "h264dvr") {
		return "H264DVR"
	}
	if strings.Contains(low, "rtprtspflyer") {
		return "RtpRtspFlyer"
	}
	if strings.Contains(low, "rtsp server") || strings.Contains(low, "rtsp") {
		return "RTSP"
	}

	// fallback: return as-is if we don't recognize it
	if s != "" {
		return s
	}
	return "RTSP"
}

// AnalyzeWebContent performs deep analysis of web content for brand detection
func AnalyzeWebContent(body string) DetectResult {
	// Look for specific web interface patterns
	webPatterns := map[string]*regexp.Regexp{
		"Hikvision": regexp.MustCompile(`(?i)(?:hikvision|hik-connect|ivms|web service|login\.jsp|main\.jsp|hikvision.*?version.*?(\d+\.\d+\.\d+))`),
		"Dahua":     regexp.MustCompile(`(?i)(?:dahua|dss|smartpss|dmss|login\.html|main\.html|dahua.*?version.*?(\d+\.\d+\.\d+))`),
		"Axis":      regexp.MustCompile(`(?i)(?:axis|axis communications|axis camera|axis mjpg|axis-cgi|axis.*?version.*?(\d+\.\d+\.\d+))`),
		"Sony":      regexp.MustCompile(`(?i)(?:sony|ipela|snc|sony network camera|sony.*?version.*?(\d+\.\d+\.\d+))`),
		"Bosch":     regexp.MustCompile(`(?i)(?:bosch|flexidome|dinion|autodome|security systems|bosch.*?version.*?(\d+\.\d+\.\d+))`),
		"Samsung":   regexp.MustCompile(`(?i)(?:samsung|hanwha|wisenet|samsung techwin|samsung.*?version.*?(\d+\.\d+\.\d+))`),
		"Panasonic": regexp.MustCompile(`(?i)(?:panasonic|wv|bb|blc|network camera|panasonic.*?version.*?(\d+\.\d+\.\d+))`),
		"Vivotek":   regexp.MustCompile(`(?i)(?:vivotek|fd|sd|ip camera|network camera|vivotek.*?version.*?(\d+\.\d+\.\d+))`),
		"CP Plus":   regexp.MustCompile(`(?i)(?:cp plus|cpplus|cp-plus|cp_plus|cp plus.*?version.*?(\d+\.\d+\.\d+))`),
	}

	for brand, pattern := range webPatterns {
		matches := pattern.FindStringSubmatch(body)
		if len(matches) > 0 {
			version := ""
			if len(matches) > 1 {
				version = matches[1]
			}
			note := "Web interface detected"
			if version != "" {
				note += " | Version: " + version
			}
			return DetectResult{Brand: brand, Note: note, Version: version}
		}
	}

	return DetectResult{Brand: "", Note: "", Version: ""}
}

// ExtractSoftwareInfo extracts software information from web content
func ExtractSoftwareInfo(body string) map[string]string {
	info := make(map[string]string)

	// Common software version patterns
	patterns := map[string]*regexp.Regexp{
		"firmware":   regexp.MustCompile(`(?i)(?:firmware|fw).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
		"software":   regexp.MustCompile(`(?i)(?:software|sw).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
		"version":    regexp.MustCompile(`(?i)(?:version|ver).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
		"build":      regexp.MustCompile(`(?i)(?:build|bld).*?(\d+\.\d+\.\d+(?:\.\d+)?)`),
		"release":    regexp.MustCompile(`(?i)(?:release|rel).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
		"kernel":     regexp.MustCompile(`(?i)(?:kernel|kern).*?(\d+\.\d+\.\d+(?:\.\d+)?)`),
		"bootloader": regexp.MustCompile(`(?i)(?:bootloader|boot).*?v?(\d+\.\d+\.\d+(?:\.\d+)?)`),
	}

	for key, pattern := range patterns {
		matches := pattern.FindStringSubmatch(body)
		if len(matches) > 1 {
			info[key] = matches[1]
		}
	}

	return info
}

// DetectLoginSystem detects the login system used by the camera
func DetectLoginSystem(body string) string {
	loginPatterns := map[string]*regexp.Regexp{
		"Hikvision": regexp.MustCompile(`(?i)(?:hikvision|hik-connect|ivms|login\.jsp)`),
		"Dahua":     regexp.MustCompile(`(?i)(?:dahua|dss|smartpss|dmss|login\.html)`),
		"Axis":      regexp.MustCompile(`(?i)(?:axis|axis-cgi|axis communications)`),
		"Sony":      regexp.MustCompile(`(?i)(?:sony|ipela|snc)`),
		"Bosch":     regexp.MustCompile(`(?i)(?:bosch|flexidome|dinion)`),
		"Samsung":   regexp.MustCompile(`(?i)(?:samsung|hanwha|wisenet)`),
		"Panasonic": regexp.MustCompile(`(?i)(?:panasonic|wv|bb|blc)`),
		"Vivotek":   regexp.MustCompile(`(?i)(?:vivotek|fd|sd)`),
		"Generic":   regexp.MustCompile(`(?i)(?:login|admin|webadmin|viewer)`),
	}

	for system, pattern := range loginPatterns {
		if pattern.MatchString(body) {
			return system
		}
	}

	return "Unknown"
}

func CVEsForBrand(brand string) []string { return cvedb.ForBrand(strings.ToLower(brand)) }
func CVELinks(cves []string) []string {
	out := make([]string, 0, len(cves))
	for _, c := range cves {
		out = append(out, "https://nvd.nist.gov/vuln/detail/"+c)
	}
	return out
}
