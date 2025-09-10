package portscan

import (
	"context"
	"testing"
	"time"
)

func BenchmarkMasscanParsing(b *testing.B) {
	scanner := &MasscanScanner{
		cfg: MasscanConfig{Debug: false},
	}

	// Test data simulating masscan output
	testLines := []string{
		"Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2025-09-09 23:44:48 GMT",
		"Initiating SYN Stealth Scan",
		"Scanning 1 hosts [3 ports/host]",
		"Discovered open port 80/tcp on 192.168.1.1",
		"Discovered open port 443/tcp on 192.168.1.1",
		"Discovered open port 8080/tcp on 192.168.1.2",
		"open tcp 22 192.168.1.3 1234567890", // Old format
		"# Comment line",
		"",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Simulate parsing without actual file I/O
		for _, line := range testLines {
			if len(line) == 0 || line[0] == '#' {
				continue
			}

			skipPrefixes := []string{"Starting masscan", "Initiating", "Scanning"}
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

			discoveredPrefix := "Discovered open port"
			if len(line) > len(discoveredPrefix) && line[:len(discoveredPrefix)] == discoveredPrefix {
				scanner.parseDiscoveredPort(line)
			} else if len(line) > 4 && line[:4] == "open" {
				scanner.parseOldFormat(line)
			}
		}
	}
}

func BenchmarkPortStringBuilding(b *testing.B) {
	ports := []int{80, 443, 8080, 8443, 22, 21, 25, 53, 110, 143, 993, 995, 3389, 5900, 5901}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildPortString(ports)
	}
}

func BenchmarkLocalhostDetection(b *testing.B) {
	scanner := &HybridScanner{}
	targets := []string{"192.168.1.1", "10.0.0.1", "127.0.0.1", "localhost", "8.8.8.8", "127.1.1.1"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.hasLocalhostTargets(targets)
	}
}

func BenchmarkCCTVPortsGeneration(b *testing.B) {
	scanner := &MasscanScanner{
		cfg: MasscanConfig{Ports: "0-65535"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.getPortsToScan()
	}
}

func BenchmarkMasscanScannerCreation(b *testing.B) {
	cfg := MasscanConfig{
		Ports: "80,443,8080",
		Rate:  1000,
		Debug: false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewMasscanScanner(cfg)
	}
}

func BenchmarkNaabuScannerCreation(b *testing.B) {
	cfg := NaabuConfig{
		Ports: "80,443,8080",
		Rate:  1000,
		Debug: false,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewNaabuScanner(cfg)
	}
}

// BenchmarkHybridScan simulates the hybrid scanning process
func BenchmarkHybridScan(b *testing.B) {
	cfg := HybridConfig{
		Ports: "80,443,8080",
		Rate:  1000,
		Debug: false,
	}
	scanner := NewHybridScanner(cfg)
	targets := []string{"192.168.1.1"}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// This will fail quickly due to timeout, but tests the setup performance
		scanner.Scan(ctx, targets)
	}
}
