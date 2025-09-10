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
	Ports     string
	Rate      int
	Retry     int
	Wait      int
	Adapter   string
	AdapterIP string
	ExtraArgs []string
	Debug     bool
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

	// Configure naabu options using the official pattern
	scanType := "CONNECT" // Default to connect scan
	if os.Geteuid() == 0 {
		scanType = "SYN" // Use SYN scan if running as root
	}

	if s.cfg.Debug {
		log.Printf("DEBUG: Using naabu scan type: %s (running as root: %v)", scanType, os.Geteuid() == 0)
	}

	options := &runner.Options{
		Host:      goflags.StringSlice(targets),
		Ports:     s.cfg.Ports,
		Rate:      s.cfg.Rate,
		Retries:   s.cfg.Retry,
		ScanType:  scanType,
		SourceIP:  s.cfg.AdapterIP,
		Interface: s.cfg.Adapter,
		Silent:    !s.cfg.Debug,
		Verbose:   s.cfg.Debug,
		Debug:     s.cfg.Debug,
		Timeout:   5 * time.Second, // Add timeout to prevent hanging
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

	defer naabuRunner.Close()

	// Execute the scan
	if err := naabuRunner.RunEnumeration(ctx); err != nil {
		return nil, fmt.Errorf("naabu scan failed: %w", err)
	}

	if s.cfg.Debug {
		log.Printf("DEBUG: Naabu discovered %d hosts with ports", len(results))
	}

	return results, nil
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
	verifyCfg.Rate = s.cfg.Rate / 2 // Slower rate for verification

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
		Host:   goflags.StringSlice([]string{"127.0.0.1"}),
		Ports:  "80",
		Rate:   100,
		Silent: true,
	}

	_, err := runner.NewRunner(options)
	if err != nil {
		return fmt.Errorf("naabu not available: %w", err)
	}

	log.Printf("Naabu installation validated")
	return nil
}
