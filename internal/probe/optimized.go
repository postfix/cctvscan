package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/postfix/cctvscan/internal/util"
)

// OptimizedProbeResult holds all probe results for a host
type OptimizedProbeResult struct {
	HTTPMeta    HTTPMeta
	LoginPages  []string
	RTSPInfo    RTSPInfo
	ONVIFResult string
	MJPEGPaths  []string
}

// OptimizedProbe performs all probes concurrently for better performance
func OptimizedProbe(ctx context.Context, host string, ports []int) OptimizedProbeResult {
	result := OptimizedProbeResult{}

	// Filter ports once
	httpPorts := FilterHTTPish(ports)
	rtspPorts := FilterRTSP(ports)

	// Use WaitGroup for concurrent processing
	var wg sync.WaitGroup

	// HTTP metadata probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		result.HTTPMeta = ProbeHTTPMeta(ctx, host, httpPorts)
	}()

	// Login pages probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		result.LoginPages = FindLoginPages(ctx, host, httpPorts)
	}()

	// RTSP probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(rtspPorts) > 0 {
			result.RTSPInfo = ProbeRTSP(ctx, host, rtspPorts)
		}
	}()

	// ONVIF probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		result.ONVIFResult = ProbeONVIF(ctx, host)
	}()

	// MJPEG paths probe
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(httpPorts) > 0 {
			result.MJPEGPaths = FindMJPEGPaths(ctx, host, httpPorts)
		}
	}()

	wg.Wait()
	return result
}

// FindMJPEGPaths efficiently finds MJPEG stream paths
func FindMJPEGPaths(ctx context.Context, host string, ports []int) []string {
	var foundPaths []string
	var mu sync.Mutex

	// Create optimized HTTP client
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			MaxIdleConns:      10,
			IdleConnTimeout:   30 * time.Second,
		},
	}

	// Process ports concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 5) // Limit concurrent requests

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			scheme := "http"
			if isHTTPS(p) {
				scheme = "https"
			}
			baseURL := scheme + "://" + net.JoinHostPort(host, util.Itoa(p))

			// Test MJPEG paths concurrently
			var pathWg sync.WaitGroup
			for _, path := range MJPEGPaths {
				pathWg.Add(1)
				go func(mjpegPath string) {
					defer pathWg.Done()

					url := baseURL + mjpegPath
					req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
					if err != nil {
						return
					}

					req.Header.Set("User-Agent", "CCTVTool/1.0")
					resp, err := client.Do(req)
					if err != nil {
						return
					}
					defer resp.Body.Close()

					// Check if it's a valid MJPEG stream
					contentType := resp.Header.Get("Content-Type")
					if isMJPEGContentType(contentType) && resp.StatusCode == 200 {
						mu.Lock()
						foundPaths = append(foundPaths, url)
						mu.Unlock()
					}
				}(path)
			}
			pathWg.Wait()
		}(port)
	}

	wg.Wait()
	return util.Uniq(foundPaths)
}

// isMJPEGContentType checks if content type indicates MJPEG stream
func isMJPEGContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	mjpegTypes := []string{
		"image/jpeg", "image/jpg", "image/pjpeg",
		"multipart/x-mixed-replace",
		"video/mjpeg", "video/x-motion-jpeg",
	}

	for _, mjpegType := range mjpegTypes {
		if strings.Contains(ct, mjpegType) {
			return true
		}
	}
	return false
}

// OptimizedHTTPMeta performs HTTP metadata collection with caching
type HTTPMetaCache struct {
	cache map[string]HTTPMeta
	mutex sync.RWMutex
}

var httpMetaCache = &HTTPMetaCache{
	cache: make(map[string]HTTPMeta),
}

// GetCachedHTTPMeta returns cached HTTP metadata or probes if not cached
func GetCachedHTTPMeta(ctx context.Context, host string, ports []int) HTTPMeta {
	key := fmt.Sprintf("%s:%v", host, ports)

	httpMetaCache.mutex.RLock()
	if cached, exists := httpMetaCache.cache[key]; exists {
		httpMetaCache.mutex.RUnlock()
		return cached
	}
	httpMetaCache.mutex.RUnlock()

	// Probe and cache
	meta := ProbeHTTPMeta(ctx, host, ports)

	httpMetaCache.mutex.Lock()
	httpMetaCache.cache[key] = meta
	httpMetaCache.mutex.Unlock()

	return meta
}

// OptimizedLoginPageFinder uses concurrent requests for faster login page discovery
func OptimizedLoginPageFinder(ctx context.Context, host string, ports []int) []string {
	var foundPages []string
	var mu sync.Mutex

	// Optimized HTTP client
	client := &http.Client{
		Timeout: 1 * time.Second, // Shorter timeout for faster scanning
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			MaxIdleConns:      20,
			IdleConnTimeout:   10 * time.Second,
		},
	}

	// Use semaphore to limit concurrent requests
	semaphore := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			scheme := "http"
			if isHTTPS(p) {
				scheme = "https"
			}
			baseURL := scheme + "://" + net.JoinHostPort(host, util.Itoa(p))

			// Test login paths concurrently
			var pathWg sync.WaitGroup
			for _, path := range CameraPaths {
				pathWg.Add(1)
				go func(loginPath string) {
					defer pathWg.Done()

					url := baseURL + loginPath
					req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
					if err != nil {
						return
					}

					resp, err := client.Do(req)
					if err != nil {
						return
					}
					defer resp.Body.Close()

					// Check for valid login pages
					if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 || resp.Header.Get("WWW-Authenticate") != "" {
						mu.Lock()
						foundPages = append(foundPages, url)
						mu.Unlock()
					}
				}(path)
			}
			pathWg.Wait()
		}(port)
	}

	wg.Wait()
	return util.Uniq(foundPages)
}
