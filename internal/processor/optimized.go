package processor

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/postfix/cctvscan/internal/credbrute"
	"github.com/postfix/cctvscan/internal/fingerprint"
	"github.com/postfix/cctvscan/internal/probe"
	"github.com/postfix/cctvscan/internal/streams"
)

// HostResult contains all results for a single host
type HostResult struct {
	Host        string
	Ports       []int
	HTTPPorts   []int
	RTSPPorts   []int
	HTTPMeta    probe.HTTPMeta
	LoginPages  []string
	RTSPInfo    probe.RTSPInfo
	ONVIFResult string
	MJPEGPaths  []string
	Brand       string
	BrandNote   string
	CVEs        []string
	Credentials string
	// Enhanced detection results
	CameraDetection probe.CameraDetectionResult
	StreamResults   []streams.StreamResult
	Error           error
}

// OptimizedProcessor handles concurrent processing of multiple hosts
type OptimizedProcessor struct {
	debug     bool
	credsFile string
	outputDir string
}

// NewOptimizedProcessor creates a new optimized processor
func NewOptimizedProcessor(debug bool, credsFile, outputDir string) *OptimizedProcessor {
	return &OptimizedProcessor{
		debug:     debug,
		credsFile: credsFile,
		outputDir: outputDir,
	}
}

// ProcessHosts processes multiple hosts concurrently
func (p *OptimizedProcessor) ProcessHosts(ctx context.Context, results map[string][]int) []HostResult {
	var hostResults []HostResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Limit concurrent host processing
	semaphore := make(chan struct{}, 5)

	for host, ports := range results {
		wg.Add(1)
		go func(h string, portList []int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result := p.processHost(ctx, h, portList)

			mu.Lock()
			hostResults = append(hostResults, result)
			mu.Unlock()
		}(host, ports)
	}

	wg.Wait()
	return hostResults
}

// processHost processes a single host with all optimizations
func (p *OptimizedProcessor) processHost(ctx context.Context, host string, ports []int) HostResult {
	result := HostResult{
		Host:  host,
		Ports: ports,
	}

	if p.debug {
		log.Printf("DEBUG: Processing host %s with ports %v", host, ports)
	}

	// Filter ports
	result.HTTPPorts = probe.FilterHTTPish(ports)
	result.RTSPPorts = probe.FilterRTSP(ports)

	// Use optimized probe for concurrent processing
	probeResult := probe.OptimizedProbe(ctx, host, ports)
	result.HTTPMeta = probeResult.HTTPMeta
	result.LoginPages = probeResult.LoginPages
	result.RTSPInfo = probeResult.RTSPInfo
	result.ONVIFResult = probeResult.ONVIFResult
	result.MJPEGPaths = probeResult.MJPEGPaths

	// Brand detection with caching
	result.Brand, result.BrandNote = fingerprint.OptimizedDetect(
		result.HTTPMeta.Server,
		result.HTTPMeta.BodySnippet,
		"",
	)

	// CVE lookup if brand detected
	if result.Brand != "" {
		result.CVEs = fingerprint.OptimizedCVEsForBrand(result.Brand)
	}

	// Credential brute force if login pages found
	if len(result.LoginPages) > 0 {
		if _, err := os.Stat(p.credsFile); !os.IsNotExist(err) {
			result.Credentials = credbrute.OptimizedBruteForce(
				ctx, host, result.LoginPages, p.credsFile, 5*time.Second,
			)
		}
	}

	// Enhanced camera detection
	if len(result.Ports) > 0 {
		if p.debug {
			log.Printf("DEBUG: Running enhanced camera detection on %s with ports %v", host, result.Ports)
		}
		cameraDetections := probe.DetectCamera(ctx, host, result.Ports)
		if len(cameraDetections) > 0 {
			// Use the first detection result (most relevant)
			result.CameraDetection = cameraDetections[0]
			if p.debug {
				log.Printf("DEBUG: Camera detection result: %+v", result.CameraDetection)
			}
		} else if p.debug {
			log.Printf("DEBUG: No camera detections found for %s", host)
		}
	}

	// Comprehensive stream detection
	if len(result.Ports) > 0 {
		outputDir := p.outputDir + "/streams"
		if p.debug {
			log.Printf("DEBUG: Running comprehensive stream detection on %s with ports %v", host, result.Ports)
		}
		result.StreamResults = streams.DetectStreams(ctx, host, result.Ports, outputDir)
		if p.debug {
			log.Printf("DEBUG: Found %d streams for %s", len(result.StreamResults), host)
		}
	}

	// MJPEG stream processing (legacy)
	if len(result.HTTPPorts) > 0 {
		go func() {
			outputDir := p.outputDir + "/snapshots"
			if p.debug {
				log.Printf("DEBUG: Saving snapshots to: %s", outputDir)
			}
			streams.TryMJPEG(ctx, host, result.HTTPPorts, outputDir)
		}()
	}

	return result
}

// PrintResults prints the results in a formatted way
func (p *OptimizedProcessor) PrintResults(results []HostResult) {
	for _, result := range results {
		fmt.Printf("\n=== Processing %s ===\n", result.Host)
		fmt.Printf("Open ports: %v\n", result.Ports)
		fmt.Printf("HTTP ports: %v\n", result.HTTPPorts)
		fmt.Printf("RTSP ports: %v\n", result.RTSPPorts)

		// HTTP Server info
		if result.HTTPMeta.Server != "" {
			fmt.Printf("HTTP Server: %s\n", result.HTTPMeta.Server)
			if p.debug && result.HTTPMeta.BodySnippet != "" {
				log.Printf("DEBUG: HTTP body snippet: %s", result.HTTPMeta.BodySnippet)
			}
		}

		// Login pages
		if len(result.LoginPages) > 0 {
			fmt.Printf("Login pages: %v\n", result.LoginPages)
		}

		// RTSP info
		if result.RTSPInfo.Any {
			fmt.Printf("RTSP Server: %s\n", result.RTSPInfo.Server)
			fmt.Printf("RTSP Public: %s\n", result.RTSPInfo.Public)
		}

		// Brand detection
		if result.Brand != "" {
			fmt.Printf("Brand: %s", result.Brand)
			if result.BrandNote != "" {
				fmt.Printf(" (%s)", result.BrandNote)
			}
			fmt.Println()

			// CVEs
			if len(result.CVEs) > 0 {
				fmt.Printf("Known CVEs: %v\n", result.CVEs)
				fmt.Printf("CVE Links: %v\n", fingerprint.OptimizedCVELinks(result.CVEs))
			}
		}

		// Credentials
		if result.Credentials != "" {
			fmt.Printf("✓ Default credentials found: %s\n", result.Credentials)
		} else if len(result.LoginPages) > 0 {
			fmt.Println("✗ No default credentials found")
		}

		// Enhanced camera detection
		if result.CameraDetection.IsCamera {
			fmt.Printf("🎥 Camera Detected: %s\n", result.CameraDetection.Brand)
			if result.CameraDetection.Model != "" {
				fmt.Printf("   Model: %s\n", result.CameraDetection.Model)
			}
			if result.CameraDetection.ServerHeader != "" {
				fmt.Printf("   Server: %s\n", result.CameraDetection.ServerHeader)
			}
			if len(result.CameraDetection.Indicators) > 0 {
				fmt.Printf("   Indicators: %v\n", result.CameraDetection.Indicators)
			}
			if result.CameraDetection.AuthRequired {
				fmt.Printf("   Auth Required: %s\n", result.CameraDetection.AuthType)
			}
			if len(result.CameraDetection.Endpoints) > 0 {
				fmt.Printf("   Endpoints: %v\n", result.CameraDetection.Endpoints)
			}
		}

		// Stream detection results
		if len(result.StreamResults) > 0 {
			fmt.Printf("📺 Streams Found (%d):\n", len(result.StreamResults))
			for _, stream := range result.StreamResults {
				fmt.Printf("   %s: %s (%s)\n", stream.Type, stream.URL, stream.ContentType)
			}
		}

		// MJPEG streams (legacy)
		if len(result.HTTPPorts) > 0 {
			fmt.Println("Checking for MJPEG streams...")
		}

		// ONVIF
		if result.ONVIFResult != "" {
			fmt.Printf("ONVIF: %s\n", result.ONVIFResult)
		}

		fmt.Println()
	}
}

// GetPerformanceStats returns performance statistics
func GetPerformanceStats() map[string]interface{} {
	stats := make(map[string]interface{})

	// Brand cache stats
	totalEntries, cveEntries := fingerprint.GetCacheStats()
	stats["brand_cache_entries"] = totalEntries
	stats["cve_cache_entries"] = cveEntries

	return stats
}
