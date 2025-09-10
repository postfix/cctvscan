package portscan

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
)

// Shared localhost detection to avoid duplicate work
var (
	localhostCache = make(map[string]bool)
	localhostMutex sync.RWMutex
)

// HybridConfig holds configuration for the hybrid scanner
type HybridConfig struct {
	Ports     string
	Rate      int
	Retry     int
	Wait      int
	Adapter   string
	AdapterIP string
	ExtraArgs []string
	Debug     bool
}

// HybridScanner combines masscan for discovery and naabu for verification
type HybridScanner struct {
	cfg HybridConfig
}

// NewHybridScanner creates a new hybrid scanner instance
func NewHybridScanner(cfg HybridConfig) *HybridScanner {
	return &HybridScanner{cfg: cfg}
}

// Scan performs hybrid scanning: masscan discovery + naabu verification
func (s *HybridScanner) Scan(ctx context.Context, targets []string) (map[string][]int, error) {
	if len(targets) == 0 {
		return map[string][]int{}, nil
	}

	// Check if we have localhost targets
	hasLocalhost := s.hasLocalhostTargets(targets)

	var discoveredPorts map[string][]int
	var err error

	if hasLocalhost {
		// For localhost targets, use naabu only
		if s.cfg.Debug {
			log.Printf("DEBUG: Detected localhost targets, using naabu for discovery")
		}

		naabuCfg := NaabuConfig{
			Ports:     s.cfg.Ports,
			Rate:      s.cfg.Rate,
			Retry:     s.cfg.Retry,
			Wait:      s.cfg.Wait,
			Adapter:   s.cfg.Adapter,
			AdapterIP: s.cfg.AdapterIP,
			ExtraArgs: s.cfg.ExtraArgs,
			Debug:     s.cfg.Debug,
		}

		naabuScanner := NewNaabuScanner(naabuCfg)
		discoveredPorts, err = naabuScanner.Scan(ctx, targets)
		if err != nil {
			return nil, fmt.Errorf("naabu discovery failed: %w", err)
		}
	} else {
		// For external targets, use masscan for discovery
		if s.cfg.Debug {
			log.Printf("DEBUG: Using masscan for external target discovery")
		}

		masscanCfg := MasscanConfig{
			Ports:     s.cfg.Ports,
			Rate:      s.cfg.Rate,
			Adapter:   s.cfg.Adapter,
			AdapterIP: s.cfg.AdapterIP,
			Debug:     s.cfg.Debug,
		}

		masscanScanner := NewMasscanScanner(masscanCfg)
		discoveredPorts, err = masscanScanner.Scan(ctx, targets)
		if err != nil {
			return nil, fmt.Errorf("masscan discovery failed: %w", err)
		}
	}

	if s.cfg.Debug {
		log.Printf("DEBUG: Discovery phase found %d hosts with ports", len(discoveredPorts))
	}

	// If no ports discovered, return empty results
	if len(discoveredPorts) == 0 {
		return discoveredPorts, nil
	}

	// Step 2: Use naabu for verification of discovered ports
	naabuCfg := NaabuConfig{
		Ports:     s.cfg.Ports,
		Rate:      s.cfg.Rate / 2, // Slower rate for verification
		Retry:     s.cfg.Retry,
		Wait:      s.cfg.Wait,
		Adapter:   s.cfg.Adapter,
		AdapterIP: s.cfg.AdapterIP,
		ExtraArgs: s.cfg.ExtraArgs,
		Debug:     s.cfg.Debug,
	}

	naabuScanner := NewNaabuScanner(naabuCfg)
	verifiedPorts, err := naabuScanner.VerifyPorts(ctx, discoveredPorts)
	if err != nil {
		if s.cfg.Debug {
			log.Printf("DEBUG: Naabu verification failed, using discovery results: %v", err)
		}
		// Fallback to discovery results if naabu verification fails
		return discoveredPorts, nil
	}

	if s.cfg.Debug {
		log.Printf("DEBUG: Verification phase confirmed %d hosts with ports", len(verifiedPorts))
	}

	return verifiedPorts, nil
}

// hasLocalhostTargets checks if any targets are localhost addresses with caching
func (s *HybridScanner) hasLocalhostTargets(targets []string) bool {
	for _, target := range targets {
		// Check cache first
		localhostMutex.RLock()
		if isLocalhost, exists := localhostCache[target]; exists {
			localhostMutex.RUnlock()
			if isLocalhost {
				return true
			}
			continue
		}
		localhostMutex.RUnlock()

		// Check if localhost and cache result
		isLocalhost := target == "127.0.0.1" || target == "localhost" || strings.HasPrefix(target, "127.")

		localhostMutex.Lock()
		localhostCache[target] = isLocalhost
		localhostMutex.Unlock()

		if isLocalhost {
			return true
		}
	}
	return false
}

// ValidateInstallation checks if both masscan and naabu are available
func ValidateInstallation() error {
	// Validate masscan
	if err := ValidateMasscanInstallation(); err != nil {
		log.Printf("WARNING: Masscan validation failed: %v", err)
	}

	// Validate naabu
	if err := ValidateNaabuInstallation(); err != nil {
		log.Printf("WARNING: Naabu validation failed: %v", err)
	}

	return nil
}
