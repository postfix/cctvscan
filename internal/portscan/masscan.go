package portscan

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/postfix/cctvscan/internal/probe"
)

// MasscanConfig holds configuration for masscan scanning
type MasscanConfig struct {
	Ports     string
	Rate      int
	Adapter   string
	AdapterIP string
	Debug     bool
}

// MasscanScanner uses masscan for high-speed SYN scanning
type MasscanScanner struct {
	cfg        MasscanConfig
	portCache  map[string]string // Cache for port strings to avoid repeated generation
	cacheMutex sync.RWMutex
}

// NewMasscanScanner creates a new masscan scanner instance
func NewMasscanScanner(cfg MasscanConfig) *MasscanScanner {
	return &MasscanScanner{
		cfg:       cfg,
		portCache: make(map[string]string),
	}
}

// Scan performs masscan discovery for the given targets
func (s *MasscanScanner) Scan(ctx context.Context, targets []string) (map[string][]int, error) {
	if len(targets) == 0 {
		return map[string][]int{}, nil
	}

	// Check if we have localhost targets that need special handling
	hasLocalhost := s.hasLocalhostTargets(targets)

	// For localhost targets, return empty results as masscan can't handle them properly
	if hasLocalhost {
		if s.cfg.Debug {
			log.Printf("DEBUG: Detected localhost targets, masscan cannot scan localhost properly")
		}
		return map[string][]int{}, nil
	}

	// Use specialized CCTV camera ports if default port range is specified
	portsToScan := s.getPortsToScan()
	if s.cfg.Debug {
		log.Printf("DEBUG: Using ports: %s", portsToScan)
	}

	// Build masscan command
	args := []string{
		"--rate", strconv.Itoa(s.cfg.Rate),
		"--open-only",
		"-p", portsToScan,
	}

	// Add interface if specified
	if s.cfg.Adapter != "" {
		args = append(args, "--interface", s.cfg.Adapter)
	}

	// Add source IP if specified
	if s.cfg.AdapterIP != "" {
		args = append(args, "--source-ip", s.cfg.AdapterIP)
	}

	// Add targets
	args = append(args, targets...)

	if s.cfg.Debug {
		log.Printf("DEBUG: Running masscan with args: %v", args)
	}

	// Execute masscan
	cmd := exec.CommandContext(ctx, "masscan", args...)
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start masscan: %w", err)
	}

	// Parse masscan output with optimized parsing
	results := s.parseMasscanOutput(stdout)

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("masscan execution failed: %w", err)
	}

	if s.cfg.Debug {
		log.Printf("DEBUG: Masscan discovered %d hosts with ports", len(results))
	}

	return results, nil
}

// getPortsToScan returns the ports to scan with caching
func (s *MasscanScanner) getPortsToScan() string {
	if s.cfg.Ports == "0-65535" || s.cfg.Ports == "" {
		s.cacheMutex.RLock()
		if cached, exists := s.portCache["cctv"]; exists {
			s.cacheMutex.RUnlock()
			return cached
		}
		s.cacheMutex.RUnlock()

		ports := probe.CameraPortsString()
		s.cacheMutex.Lock()
		s.portCache["cctv"] = ports
		s.cacheMutex.Unlock()
		return ports
	}
	return s.cfg.Ports
}

// parseMasscanOutput efficiently parses masscan output
func (s *MasscanScanner) parseMasscanOutput(stdout io.ReadCloser) map[string][]int {
	results := make(map[string][]int)
	scanner := bufio.NewScanner(stdout)

	// Pre-allocate buffers for better performance
	const maxCapacity = 1024 * 1024 // 1MB buffer
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	// Pre-compile common prefixes for faster checking
	skipPrefixes := []string{"#", "Starting masscan", "Initiating", "Scanning"}
	discoveredPrefix := "Discovered open port"

	for scanner.Scan() {
		line := scanner.Text()

		// Fast skip for empty lines and comments
		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Fast skip for known prefixes
		skip := false
		for _, prefix := range skipPrefixes {
			if len(line) >= len(prefix) && line[:len(prefix)] == prefix {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// Parse discovered ports with optimized string operations
		if len(line) > len(discoveredPrefix) && line[:len(discoveredPrefix)] == discoveredPrefix {
			if port, host := s.parseDiscoveredPort(line); port > 0 && host != "" {
				results[host] = append(results[host], port)
				if s.cfg.Debug {
					log.Printf("DEBUG: Masscan discovered port %d on %s", port, host)
				}
			}
		} else if len(line) > 4 && line[:4] == "open" {
			// Handle old format: "open tcp 80 192.168.1.1 1234567890"
			if port, host := s.parseOldFormat(line); port > 0 && host != "" {
				results[host] = append(results[host], port)
				if s.cfg.Debug {
					log.Printf("DEBUG: Masscan discovered port %d on %s (old format)", port, host)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("WARNING: Error reading masscan output: %v", err)
	}

	return results
}

// parseDiscoveredPort parses "Discovered open port 80/tcp on 192.168.1.1" format
func (s *MasscanScanner) parseDiscoveredPort(line string) (int, string) {
	// Find the port part (after "Discovered open port ")
	start := len("Discovered open port ")
	if len(line) <= start {
		return 0, ""
	}

	// Find the port number before "/tcp"
	slashPos := strings.Index(line[start:], "/tcp")
	if slashPos == -1 {
		return 0, ""
	}

	portStr := line[start : start+slashPos]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, ""
	}

	// Find the host after " on "
	onPos := strings.Index(line, " on ")
	if onPos == -1 {
		return 0, ""
	}

	host := line[onPos+4:]
	return port, host
}

// parseOldFormat parses "open tcp 80 192.168.1.1 1234567890" format
func (s *MasscanScanner) parseOldFormat(line string) (int, string) {
	parts := strings.Fields(line)
	if len(parts) < 4 || parts[0] != "open" || parts[1] != "tcp" {
		return 0, ""
	}

	port, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, ""
	}

	return port, parts[3]
}

// hasLocalhostTargets checks if any targets are localhost addresses
func (s *MasscanScanner) hasLocalhostTargets(targets []string) bool {
	for _, target := range targets {
		if target == "127.0.0.1" || target == "localhost" || strings.HasPrefix(target, "127.") {
			return true
		}
	}
	return false
}

// GetCCTVPorts returns the specialized CCTV camera ports for masscan
func GetCCTVPorts() string {
	return probe.CameraPortsString()
}

// ValidateMasscanInstallation checks if masscan is installed and accessible
func ValidateMasscanInstallation() error {
	cmd := exec.Command("masscan", "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("masscan not found: %w", err)
	}

	// Check if masscan has required capabilities for SYN scanning
	cmd = exec.Command("masscan", "--health-check")
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("masscan health check failed: %w", err)
	}

	log.Printf("Masscan installation validated: %s", strings.TrimSpace(string(output)))
	return nil
}
