package portscan

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

// NaabuConfig holds configuration for naabu scanning
type NaabuConfig struct {
	Ports        string
	Rate         int
	Retry        int
	Wait         int
	Adapter      string
	AdapterIP    string
	ExtraArgs    []string
	Debug        bool
	Privileged   bool // Force privileged mode (SYN scan)
	Unprivileged bool // Force unprivileged mode (CONNECT scan)
	Timeout      time.Duration
	Threads      int
}

// NaabuScanner uses naabu for port verification and localhost scanning
type NaabuScanner struct {
	cfg NaabuConfig
}

// NewNaabuScanner creates a new naabu scanner instance
func NewNaabuScanner(cfg NaabuConfig) *NaabuScanner {
	return &NaabuScanner{cfg: cfg}
}

// Scan performs naabu scanning for the given targets
func (s *NaabuScanner) Scan(ctx context.Context, targets []string) (map[string][]int, error) {
	if len(targets) == 0 {
		return map[string][]int{}, nil
	}

	// Determine scan type based on configuration and privileges
	scanType := s.determineScanType()

	if s.cfg.Debug {
		log.Printf("DEBUG: Using naabu scan type: %s", scanType)
	}

	// Set default values if not configured
	timeout := s.cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	threads := s.cfg.Threads
	if threads == 0 {
		threads = 25 // Default thread count
	}

	options := &runner.Options{
		Host:       goflags.StringSlice(targets),
		Ports:      s.cfg.Ports,
		Rate:       s.cfg.Rate,
		Retries:    s.cfg.Retry,
		ScanType:   scanType,
		SourceIP:   s.cfg.AdapterIP,
		Interface:  s.cfg.Adapter,
		Silent:     !s.cfg.Debug,
		Verbose:    s.cfg.Debug,
		Debug:      s.cfg.Debug,
		Timeout:    timeout,
		Threads:    threads,
		WarmUpTime: 1, // Add warm-up time for SYN scans (in seconds)
	}

	if s.cfg.Debug {
		log.Printf("DEBUG: Naabu options: Host=%v, Ports=%s, Rate=%d", options.Host, options.Ports, options.Rate)
	}

	// Collect results
	results := make(map[string][]int)
	var mu sync.Mutex

	// Set up callback to collect results
	options.OnResult = func(hostResult *result.HostResult) {
		if hostResult.IP != "" && len(hostResult.Ports) > 0 {
			mu.Lock()
			for _, port := range hostResult.Ports {
				results[hostResult.IP] = append(results[hostResult.IP], port.Port)
			}
			mu.Unlock()
		}
	}

	// Create and run naabu runner
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		return nil, fmt.Errorf("failed to create naabu runner: %w", err)
	}

	// Ensure proper cleanup
	defer func() {
		if closeErr := naabuRunner.Close(); closeErr != nil && s.cfg.Debug {
			log.Printf("DEBUG: Error closing naabu runner: %v", closeErr)
		}
	}()

	// Execute the scan
	if err := naabuRunner.RunEnumeration(ctx); err != nil {
		return nil, fmt.Errorf("naabu scan failed: %w", err)
	}

	if s.cfg.Debug {
		log.Printf("DEBUG: Naabu discovered %d hosts with ports", len(results))
	}

	return results, nil
}

// determineScanType determines the appropriate scan type based on configuration and privileges
func (s *NaabuScanner) determineScanType() string {
	// If explicitly configured, use that
	if s.cfg.Privileged {
		return "SYN"
	}
	if s.cfg.Unprivileged {
		return "CONNECT"
	}

	// Auto-detect based on privileges
	// Check if running as root (Unix) or with admin privileges (Windows)
	if s.isPrivileged() {
		return "SYN"
	}

	return "CONNECT"
}

// isPrivileged checks if the process has sufficient privileges for SYN scans
func (s *NaabuScanner) isPrivileged() bool {
	// On Unix systems, check if running as root
	if os.Geteuid() == 0 {
		return true
	}

	// Additional checks could be added here for Windows or other platforms
	// For now, default to false if not root on Unix
	return false
}

// VerifyPorts verifies discovered ports using naabu
func (s *NaabuScanner) VerifyPorts(ctx context.Context, discoveredPorts map[string][]int) (map[string][]int, error) {
	if len(discoveredPorts) == 0 {
		return discoveredPorts, nil
	}

	// Convert discovered ports to naabu format
	var targets []string
	for host := range discoveredPorts {
		targets = append(targets, host)
	}

	// Build port string for naabu
	allPorts := make(map[int]bool)
	for _, ports := range discoveredPorts {
		for _, port := range ports {
			allPorts[port] = true
		}
	}

	var portList []int
	for port := range allPorts {
		portList = append(portList, port)
	}

	portStr := buildPortString(portList)

	// Update config for naabu verification
	verifyCfg := s.cfg
	verifyCfg.Ports = portStr
	verifyCfg.Rate = s.cfg.Rate / 2      // Slower rate for verification
	verifyCfg.Timeout = 10 * time.Second // Longer timeout for verification

	naabuScanner := NewNaabuScanner(verifyCfg)

	// Run naabu verification
	verifiedPorts, err := naabuScanner.Scan(ctx, targets)
	if err != nil {
		return nil, err
	}

	return verifiedPorts, nil
}

// buildPortString converts a slice of ports to naabu-compatible string
func buildPortString(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	// Pre-allocate with estimated capacity for better performance
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port)) // Use strconv.Itoa instead of fmt.Sprintf
	}

	return strings.Join(parts, ",")
}

// ValidateNaabuInstallation checks if naabu is installed and accessible
func ValidateNaabuInstallation() error {
	// Try to create a naabu runner to validate installation
	options := &runner.Options{
		Host:       goflags.StringSlice([]string{"127.0.0.1"}),
		Ports:      "80",
		Rate:       100,
		Silent:     true,
		ScanType:   "CONNECT", // Use CONNECT for validation to avoid privilege issues
		Timeout:    5 * time.Second,
		Threads:    1,
		WarmUpTime: 0,
	}

	_, err := runner.NewRunner(options)
	if err != nil {
		return fmt.Errorf("naabu not available: %w", err)
	}

	log.Printf("Naabu installation validated")
	return nil
}
