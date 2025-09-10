package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/postfix/cctvscan/internal/portscan"
	"github.com/postfix/cctvscan/internal/processor"
	"github.com/postfix/cctvscan/internal/targets"
)

var (
	portsFlag     = flag.String("ports", "0-65535", "Port range to scan (e.g., '80,443,8000-9000')")
	rateFlag      = flag.Int("rate", 1000, "Packets per second rate for naabu")
	retryFlag     = flag.Int("retry", 3, "Number of retries for port scanning")
	waitFlag      = flag.Int("wait", 1, "Seconds to wait for late replies")
	adapterFlag   = flag.String("adapter", "", "Network adapter name for naabu")
	adapterIPFlag = flag.String("adapter-ip", "", "Source IP address for naabu")
	timeoutFlag   = flag.String("timeout", "30m", "Overall scan timeout (e.g., '30m', '1h')")
	credsFlag     = flag.String("creds", "/etc/cctvscan/credentials.txt", "Credentials file for brute force")
	outputFlag    = flag.String("output", ".", "Output directory for results")
	debugFlag     = flag.Bool("debug", false, "Enable debug mode with verbose output")
	helpFlag      = flag.Bool("help", false, "Show help message")
)

func main() {
	flag.Parse()

	if *helpFlag || len(flag.Args()) == 0 {
		printHelp()
		os.Exit(0)
	}

	// Parse timeout duration
	timeout, err := time.ParseDuration(*timeoutFlag)
	if err != nil {
		log.Fatalf("Invalid timeout format: %v", err)
	}

	// Parse targets
	targetList, err := targets.Expand(flag.Args())
	if err != nil {
		log.Fatalf("Error parsing targets: %v", err)
	}

	if len(targetList) == 0 {
		log.Fatal("No valid targets found")
	}

	if *debugFlag {
		log.Printf("DEBUG: Scanning %d target(s): %v", len(targetList), targetList)
		log.Printf("DEBUG: Configuration - ports: %s, rate: %d, retry: %d, wait: %d, timeout: %v",
			*portsFlag, *rateFlag, *retryFlag, *waitFlag, timeout)
	}

	fmt.Printf("Scanning %d target(s)\n", len(targetList))

	// Configure naabu - use camera ports by default unless specified
	portsToScan := *portsFlag
	if portsToScan == "0-65535" {
		// Use camera-specific ports by default
		portsToScan = portscan.GetCCTVPorts()
		if *debugFlag {
			log.Printf("DEBUG: Using camera-specific ports: %s", portsToScan)
		}
	}

	cfg := portscan.HybridConfig{
		Ports:     portsToScan,
		Rate:      *rateFlag,
		Retry:     *retryFlag,
		Wait:      *waitFlag,
		Adapter:   *adapterFlag,
		AdapterIP: *adapterIPFlag,
		ExtraArgs: []string{"--open-only"},
		Debug:     *debugFlag,
	}

	if *debugFlag {
		log.Printf("DEBUG: Scanner config: %+v", cfg)
	}

	scanner := portscan.NewHybridScanner(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Scan targets
	results, err := scanner.Scan(ctx, targetList)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	fmt.Printf("Found %d hosts with open ports\n", len(results))

	// Use optimized processor for concurrent processing
	processor := processor.NewOptimizedProcessor(*debugFlag, *credsFlag, *outputFlag)
	hostResults := processor.ProcessHosts(ctx, results)

	// Print results
	processor.PrintResults(hostResults)

	if *debugFlag {
		log.Printf("DEBUG: Scan completed successfully")
	}
}

func printHelp() {
	fmt.Printf("Usage: %s [OPTIONS] <target> [target2 ...]\n", os.Args[0])
	fmt.Println("\nTargets can be: IP addresses, CIDR ranges, or files containing targets")
	fmt.Println("\nOptions:")
	flag.VisitAll(func(f *flag.Flag) {
		fmt.Printf("  -%-12s %s (default: %v)\n", f.Name, f.Usage, f.DefValue)
	})
	fmt.Println("\nExamples:")
	fmt.Printf("  %s 192.168.1.100\n", os.Args[0])
	fmt.Printf("  %s -rate 5000 -ports 80,443,8080 192.168.1.0/24\n", os.Args[0])
	fmt.Printf("  %s -debug -creds mycreds.txt targets.txt\n", os.Args[0])
	fmt.Println("\nCredentials file format (user:pass per line):")
	fmt.Println("  admin:admin")
	fmt.Println("  admin:12345")
	fmt.Println("  root:root")
}
