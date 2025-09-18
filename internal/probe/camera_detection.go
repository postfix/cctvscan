package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// CameraDetectionResult contains detailed camera detection information
type CameraDetectionResult struct {
	IsCamera     bool
	Brand        string
	Model        string
	ServerHeader string
	ContentType  string
	Status       int
	Keywords     []string
	Endpoints    []string
	AuthRequired bool
	AuthType     string
	PageTitle    string
	FormFields   []string
	Indicators   []string
}

// Camera server headers and keywords (expanded from Python version)
var CameraServers = map[string][]string{
	"hikvision":  {"hikvision", "dvr", "nvr", "hik-connect"},
	"dahua":      {"dahua", "dvr", "nvr", "dahua technology"},
	"axis":       {"axis", "axis communications", "axis camera"},
	"sony":       {"sony", "ipela", "sony corporation"},
	"bosch":      {"bosch", "security systems", "bosch security"},
	"samsung":    {"samsung", "samsung techwin", "samsung electronics"},
	"panasonic":  {"panasonic", "network camera", "panasonic corporation"},
	"vivotek":    {"vivotek", "network camera", "vivotek inc"},
	"cp plus":    {"cp plus", "cp-plus", "cpplus", "cp_plus", "uvr", "0401e1"},
	"foscam":     {"foscam", "foscam camera", "foscam ip camera"},
	"d-link":     {"d-link", "dlink", "d-link camera", "dlink camera"},
	"easyn":      {"easyn", "easyn camera", "easyn ip camera"},
	"edimax":     {"edimax", "edimax camera", "edimax ip camera"},
	"intellinet": {"intellinet", "intellinet camera", "intellinet ip camera"},
	"tp-link":    {"tp-link", "tplink", "tp-link camera", "tplink camera"},
	"trendnet":   {"trendnet", "trendnet camera", "trendnet ip camera"},
	"mobotix":    {"mobotix", "mobotix camera", "mobotix ip camera"},
	"generic":    {"camera", "webcam", "surveillance", "ip camera", "network camera", "dvr", "nvr", "recorder", "cctv"},
}

// Camera content types (expanded)
var CameraContentTypes = []string{
	"image/jpeg", "image/jpg", "image/pjpeg", "image/png", "image/gif",
	"multipart/x-mixed-replace",
	"video/mpeg", "video/mp4", "video/h264", "video/h265", "video/hevc",
	"video/3gpp", "video/webm", "video/ogg", "video/MP2T",
	"application/mp4", "application/sdp", "application/vnd.apple.mpegurl",
	"application/x-mpegURL", "application/octet-stream", "application/x-rtsp",
	"text/html", "application/json", "application/xml", "text/xml",
}

// Camera keywords for content analysis
var CameraKeywords = []string{
	"camera", "webcam", "surveillance", "stream", "video", "snapshot",
	"dvr", "nvr", "recorder", "cctv", "monitor", "security",
}

// DVR/NVR specific keywords
var DVRNVRKeywords = []string{
	"dvr", "nvr", "recorder", "surveillance", "cctv", "camera",
	"monitoring", "security", "alarm", "motion", "detection",
}

// Common camera endpoints for detection
var CameraEndpoints = []string{
	"/video", "/stream", "/snapshot", "/cgi-bin", "/admin", "/viewer",
	"/login", "/index.html", "/", "/live", "/mjpg", "/image",
}

// DetectCamera performs comprehensive camera detection
func DetectCamera(ctx context.Context, host string, ports []int) []CameraDetectionResult {
	var results []CameraDetectionResult

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext,
		},
	}

	for _, port := range ports {
		protocol := "http"
		if port == 443 || port == 8443 || port == 8444 {
			protocol = "https"
		}

		baseURL := fmt.Sprintf("%s://%s:%d", protocol, host, port)
		result := analyzePort(ctx, client, baseURL)
		if result.IsCamera {
			results = append(results, result)
		}
	}

	return results
}

// analyzePort analyzes a specific port for camera indicators
func analyzePort(ctx context.Context, client *http.Client, baseURL string) CameraDetectionResult {
	result := CameraDetectionResult{
		IsCamera: false,
		Status:   0,
	}

	// Check main page
	req, _ := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	req.Header.Set("User-Agent", "CCTVTool/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.Status = resp.StatusCode
	result.ServerHeader = resp.Header.Get("Server")
	result.ContentType = resp.Header.Get("Content-Type")

	// Check server headers for camera brands
	result.Brand = detectBrandFromServer(result.ServerHeader)
	if result.Brand != "" {
		result.IsCamera = true
		result.Indicators = append(result.Indicators, "Server header brand detection")
	}

	// Check content type
	if isCameraContentType(result.ContentType) {
		result.IsCamera = true
		result.Indicators = append(result.Indicators, "Camera content type")
	}

	// Check authentication
	if resp.StatusCode == 401 {
		result.AuthRequired = true
		result.AuthType = resp.Header.Get("WWW-Authenticate")
		result.Indicators = append(result.Indicators, "Authentication required")
	}

	// Analyze response content
	if resp.StatusCode == 200 {
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
		if err == nil {
			content := string(body)
			analyzeContent(&result, content)
		}
	}

	// Check camera endpoints
	result.Endpoints = checkCameraEndpoints(ctx, client, baseURL)

	// Check for DVR/NVR specific patterns
	if isDVRNVR(result) {
		result.Indicators = append(result.Indicators, "DVR/NVR device detected")
	}

	return result
}

// detectBrandFromServer detects camera brand from server header
func detectBrandFromServer(serverHeader string) string {
	serverLower := strings.ToLower(serverHeader)

	for brand, keywords := range CameraServers {
		if brand == "generic" {
			continue // Skip generic, check others first
		}
		for _, keyword := range keywords {
			if strings.Contains(serverLower, keyword) {
				return brand
			}
		}
	}

	// Check generic keywords last
	for _, keyword := range CameraServers["generic"] {
		if strings.Contains(serverLower, keyword) {
			return "generic"
		}
	}

	return ""
}

// isCameraContentType checks if content type indicates camera
func isCameraContentType(contentType string) bool {
	contentTypeLower := strings.ToLower(contentType)
	for _, ct := range CameraContentTypes {
		if strings.Contains(contentTypeLower, ct) {
			return true
		}
	}
	return false
}

// analyzeContent analyzes response content for camera indicators
func analyzeContent(result *CameraDetectionResult, content string) {
	contentLower := strings.ToLower(content)

	// Check for camera keywords
	var foundKeywords []string
	for _, keyword := range CameraKeywords {
		if strings.Contains(contentLower, keyword) {
			foundKeywords = append(foundKeywords, keyword)
		}
	}
	if len(foundKeywords) > 0 {
		result.Keywords = foundKeywords
		result.IsCamera = true
		result.Indicators = append(result.Indicators, "Camera keywords in content")
	}

	// Check for specific brand indicators
	for brand, keywords := range CameraServers {
		if brand == "generic" {
			continue
		}
		for _, keyword := range keywords {
			if strings.Contains(contentLower, keyword) {
				if result.Brand == "" {
					result.Brand = brand
				}
				result.IsCamera = true
				result.Indicators = append(result.Indicators, fmt.Sprintf("%s brand indicator", brand))
				break
			}
		}
	}

	// Extract page title
	result.PageTitle = extractPageTitle(content)
	if result.PageTitle != "" && containsCameraKeywords(result.PageTitle) {
		result.IsCamera = true
		result.Indicators = append(result.Indicators, "Camera-related page title")
	}

	// Check for login forms
	result.FormFields = extractFormFields(content)
	if len(result.FormFields) > 0 {
		result.Indicators = append(result.Indicators, "Login form detected")
	}

	// Check for specific model indicators
	result.Model = extractModelInfo(content, result.Brand)
}

// extractPageTitle extracts page title from HTML content
func extractPageTitle(content string) string {
	re := regexp.MustCompile(`<title[^>]*>(.*?)</title>`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// extractFormFields extracts form field names from HTML content
func extractFormFields(content string) []string {
	var fields []string

	// Look for input fields
	inputRe := regexp.MustCompile(`<input[^>]*name=["']([^"']*)["'][^>]*>`)
	matches := inputRe.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			field := strings.ToLower(match[1])
			if contains([]string{"username", "password", "user", "pass", "login"}, field) {
				fields = append(fields, field)
			}
		}
	}

	return fields
}

// extractModelInfo extracts model information from content
func extractModelInfo(content, brand string) string {
	contentLower := strings.ToLower(content)

	// Brand-specific model patterns
	modelPatterns := map[string][]string{
		"cp plus":   {"uvr-0401e1", "uvr0401e1", "0401e1"},
		"hikvision": {"ds-", "nvr-", "dvr-"},
		"dahua":     {"nvr", "dvr", "ipc-"},
		"axis":      {"m30", "m31", "p13", "p33"},
	}

	if patterns, exists := modelPatterns[brand]; exists {
		for _, pattern := range patterns {
			if strings.Contains(contentLower, pattern) {
				return pattern
			}
		}
	}

	return ""
}

// checkCameraEndpoints checks for common camera endpoints
func checkCameraEndpoints(ctx context.Context, client *http.Client, baseURL string) []string {
	var foundEndpoints []string

	for _, endpoint := range CameraEndpoints {
		url := baseURL + endpoint
		req, _ := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		req.Header.Set("User-Agent", "CCTVTool/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			foundEndpoints = append(foundEndpoints, url)
		}
	}

	return foundEndpoints
}

// isDVRNVR checks if the device appears to be a DVR/NVR
func isDVRNVR(result CameraDetectionResult) bool {
	// Check page title
	if result.PageTitle != "" {
		titleLower := strings.ToLower(result.PageTitle)
		for _, keyword := range DVRNVRKeywords {
			if strings.Contains(titleLower, keyword) {
				return true
			}
		}
	}

	// Check server header
	if result.ServerHeader != "" {
		serverLower := strings.ToLower(result.ServerHeader)
		for _, keyword := range DVRNVRKeywords {
			if strings.Contains(serverLower, keyword) {
				return true
			}
		}
	}

	// Check keywords
	for _, keyword := range result.Keywords {
		for _, dvrKeyword := range DVRNVRKeywords {
			if strings.Contains(strings.ToLower(keyword), dvrKeyword) {
				return true
			}
		}
	}

	return false
}

// containsCameraKeywords checks if text contains camera-related keywords
func containsCameraKeywords(text string) bool {
	textLower := strings.ToLower(text)
	for _, keyword := range CameraKeywords {
		if strings.Contains(textLower, keyword) {
			return true
		}
	}
	return false
}

// contains checks if slice contains string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
