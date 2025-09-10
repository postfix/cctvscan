// Package targets handles target specification and expansion for network scanning.
// It supports reading targets from files, command-line arguments, and CIDR expansion.
package targets

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/postfix/cctvscan/internal/util"
)

// FromArgsOrFile processes targets from command-line arguments and/or a file.
// It reads targets from the specified file (if provided), combines them with args,
// expands CIDR notations to individual IPs, and validates all targets.
// Returns a slice of unique target IP addresses or an error if any target is invalid.
func FromArgsOrFile(args []string, file string) ([]string, error) {
	lines := make([]string, 0, len(args)+10)
	if file != "" {
		f, err := os.Open(file)
		if err != nil { return nil, err }
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			s := strings.TrimSpace(sc.Text())
			if s == "" || strings.HasPrefix(s, "#") { continue }
			lines = append(lines, s)
		}
		if err := sc.Err(); err != nil { return nil, err }
	}
	lines = append(lines, args...)
	// Pre-allocate output slice with estimated capacity
	out := make([]string, 0, len(lines)*4)
	for _, t := range lines {
		if _, ipnet, err := net.ParseCIDR(t); err == nil {
			for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
				out = append(out, ip.String())
			}
			continue
		}
		if ip := net.ParseIP(t); ip != nil {
			out = append(out, ip.String())
			continue
		}
		return nil, fmt.Errorf("invalid target %q", t)
	}
	return util.Uniq(out), nil
}

// incIP increments an IP address by one.
// It handles carry-over between octets correctly for proper IP address arithmetic.
func incIP(ip net.IP) {
	for j := len(ip)-1; j>=0; j-- {
		ip[j]++
		if ip[j] != 0 { break }
	}
}

// Expand processes targets from command-line arguments, handling both
// individual IPs and files containing target lists.
func Expand(args []string) ([]string, error) {
	var targets []string
	
	for _, arg := range args {
		// Check if argument is a file
		if _, err := os.Stat(arg); err == nil {
			// Read targets from file
			f, err := os.Open(arg)
			if err != nil {
				return nil, fmt.Errorf("failed to open file %s: %v", arg, err)
			}
			defer f.Close()
			
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" && !strings.HasPrefix(line, "#") {
					targets = append(targets, line)
				}
			}
			if err := scanner.Err(); err != nil {
				return nil, fmt.Errorf("error reading file %s: %v", arg, err)
			}
		} else {
			// Treat as direct target
			targets = append(targets, arg)
		}
	}
	
	// Use FromArgsOrFile to handle CIDR expansion and validation
	return FromArgsOrFile(targets, "")
}





