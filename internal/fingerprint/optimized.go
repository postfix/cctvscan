package fingerprint

import (
	"strings"
	"sync"

	"github.com/postfix/cctvscan/internal/cvedb"
)

// BrandDetectionCache caches brand detection results
type BrandDetectionCache struct {
	cache map[string]BrandResult
	mutex sync.RWMutex
}

type BrandResult struct {
	Brand string
	Note  string
	CVEs  []string
}

var brandCache = &BrandDetectionCache{
	cache: make(map[string]BrandResult),
}

// OptimizedDetect performs brand detection with caching and optimized string operations
func OptimizedDetect(serverHdr, body, rtspServer string) (brand, note string) {
	// Create cache key
	cacheKey := strings.ToLower(serverHdr + "|" + body + "|" + rtspServer)

	// Check cache first
	brandCache.mutex.RLock()
	if cached, exists := brandCache.cache[cacheKey]; exists {
		brandCache.mutex.RUnlock()
		return cached.Brand, cached.Note
	}
	brandCache.mutex.RUnlock()

	// Perform detection
	brand, note = detectBrand(serverHdr, body, rtspServer)

	// Cache result
	brandCache.mutex.Lock()
	brandCache.cache[cacheKey] = BrandResult{
		Brand: brand,
		Note:  note,
		CVEs:  cvedb.ForBrand(strings.ToLower(brand)),
	}
	brandCache.mutex.Unlock()

	return brand, note
}

// detectBrand performs the actual brand detection with optimized string operations
func detectBrand(serverHdr, body, rtspServer string) (brand, note string) {
	// Pre-compute lowercase versions once
	lh := strings.ToLower(serverHdr)
	lb := strings.ToLower(body)
	lr := strings.ToLower(rtspServer)

	// Use optimized string matching
	brandMatchers := []struct {
		name    string
		matcher func() bool
	}{
		{"Hikvision", func() bool {
			return containsAny(lh, brandKeysHikvision) ||
				containsAny(lb, brandKeysHikvision) ||
				strings.Contains(lr, "hik")
		}},
		{"Dahua", func() bool {
			return containsAny(lh, brandKeysDahua) ||
				containsAny(lb, brandKeysDahua) ||
				strings.Contains(lr, "dahua")
		}},
		{"Axis", func() bool {
			return containsAny(lh, brandKeysAxis) ||
				containsAny(lb, brandKeysAxis) ||
				strings.Contains(lr, "axis")
		}},
		{"Sony", func() bool {
			return containsAny(lh, brandKeysSony) ||
				containsAny(lb, brandKeysSony) ||
				strings.Contains(lr, "sony")
		}},
		{"Bosch", func() bool {
			return containsAny(lh, brandKeysBosch) ||
				containsAny(lb, brandKeysBosch) ||
				strings.Contains(lr, "bosch")
		}},
		{"Samsung", func() bool {
			return containsAny(lh, brandKeysSamsung) ||
				containsAny(lb, brandKeysSamsung) ||
				strings.Contains(lr, "samsung")
		}},
		{"Panasonic", func() bool {
			return containsAny(lh, brandKeysPanasonic) ||
				containsAny(lb, brandKeysPanasonic) ||
				strings.Contains(lr, "panasonic")
		}},
		{"Vivotek", func() bool {
			return containsAny(lh, brandKeysVivotek) ||
				containsAny(lb, brandKeysVivotek) ||
				strings.Contains(lr, "vivotek")
		}},
		{"CP Plus", func() bool {
			return strings.Contains(lb, "cp plus") ||
				strings.Contains(lb, "cpplus") ||
				strings.Contains(lb, "cp-plus") ||
				strings.Contains(lb, "cp_plus")
		}},
	}

	// Check each brand matcher
	for _, matcher := range brandMatchers {
		if matcher.matcher() {
			return matcher.name, ""
		}
	}

	// RTSP server brand detection
	if rtspServer != "" {
		if norm := normalizeRtspBrandFromServer(rtspServer); norm != "RTSP" && norm != "" {
			return norm, "RTSP server: " + rtspServer
		}
	}

	// Generic camera hints
	if containsAny(lh, brandKeysGeneric) || containsAny(lb, brandKeysGeneric) || containsAny(lr, brandKeysGeneric) {
		return "Unknown cam", ""
	}

	return "", ""
}

// containsAny optimized string matching
func containsAny(text string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(text, keyword) {
			return true
		}
	}
	return false
}

// OptimizedCVEsForBrand returns CVEs with caching
func OptimizedCVEsForBrand(brand string) []string {
	lowerBrand := strings.ToLower(brand)

	// Check cache first
	brandCache.mutex.RLock()
	for _, result := range brandCache.cache {
		if strings.ToLower(result.Brand) == lowerBrand {
			cves := make([]string, len(result.CVEs))
			copy(cves, result.CVEs)
			brandCache.mutex.RUnlock()
			return cves
		}
	}
	brandCache.mutex.RUnlock()

	// Get CVEs and cache them
	cves := cvedb.ForBrand(lowerBrand)

	// Cache the result
	brandCache.mutex.Lock()
	brandCache.cache["cve_"+lowerBrand] = BrandResult{
		Brand: brand,
		CVEs:  cves,
	}
	brandCache.mutex.Unlock()

	return cves
}

// OptimizedCVELinks returns CVE links with pre-allocated slice
func OptimizedCVELinks(cves []string) []string {
	if len(cves) == 0 {
		return nil
	}

	links := make([]string, 0, len(cves))
	for _, cve := range cves {
		links = append(links, "https://nvd.nist.gov/vuln/detail/"+cve)
	}
	return links
}

// ClearCache clears the brand detection cache
func ClearCache() {
	brandCache.mutex.Lock()
	brandCache.cache = make(map[string]BrandResult)
	brandCache.mutex.Unlock()
}

// GetCacheStats returns cache statistics
func GetCacheStats() (int, int) {
	brandCache.mutex.RLock()
	defer brandCache.mutex.RUnlock()

	totalEntries := len(brandCache.cache)
	cveEntries := 0

	for key := range brandCache.cache {
		if strings.HasPrefix(key, "cve_") {
			cveEntries++
		}
	}

	return totalEntries, cveEntries
}
