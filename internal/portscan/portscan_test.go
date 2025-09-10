package portscan

import (
	"testing"
)

func TestGetCCTVPorts(t *testing.T) {
	ports := GetCCTVPorts()
	if ports == "" {
		t.Error("GetCCTVPorts should return a non-empty string")
	}

	// Check that it contains some expected camera ports
	expectedPorts := []string{"80", "443", "554", "8080", "8443"}
	for _, expectedPort := range expectedPorts {
		if !contains(ports, expectedPort) {
			t.Errorf("Expected port %s not found in CCTV ports: %s", expectedPort, ports)
		}
	}
}

func TestBuildPortString(t *testing.T) {
	tests := []struct {
		ports    []int
		expected string
	}{
		{[]int{80, 443, 8080}, "80,443,8080"},
		{[]int{80}, "80"},
		{[]int{}, ""},
		{[]int{554, 80, 443}, "554,80,443"},
	}

	for _, test := range tests {
		result := buildPortString(test.ports)
		if result != test.expected {
			t.Errorf("buildPortString(%v) = %s, expected %s", test.ports, result, test.expected)
		}
	}
}

func TestHasLocalhostTargets(t *testing.T) {
	scanner := &HybridScanner{}

	tests := []struct {
		targets  []string
		expected bool
	}{
		{[]string{"192.168.1.1", "10.0.0.1"}, false},
		{[]string{"127.0.0.1"}, true},
		{[]string{"localhost"}, true},
		{[]string{"127.0.0.1", "192.168.1.1"}, true},
		{[]string{"127.1.1.1"}, true},
		{[]string{"192.168.1.1", "10.0.0.1", "127.0.0.1"}, true},
	}

	for _, test := range tests {
		result := scanner.hasLocalhostTargets(test.targets)
		if result != test.expected {
			t.Errorf("hasLocalhostTargets(%v) = %v, expected %v", test.targets, result, test.expected)
		}
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				containsInMiddle(s, substr))))
}

func containsInMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
