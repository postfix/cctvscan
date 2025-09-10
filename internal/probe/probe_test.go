package probe

import (
	"context"
	"testing"
	"time"
)

func TestIsHTTPS(t *testing.T) {
	tests := []struct {
		port     int
		expected bool
	}{
		{443, true},
		{8443, true},
		{80, false},
		{8080, false},
		{22, false},
	}

	for _, test := range tests {
		result := isHTTPS(test.port)
		if result != test.expected {
			t.Errorf("isHTTPS(%d) = %t, expected %t", test.port, result, test.expected)
		}
	}
}

func TestProbeONVIF_InvalidHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Test with invalid host that should timeout or fail quickly
	result := ProbeONVIF(ctx, "invalid-host-that-will-not-resolve")
	
	// Should return empty string or error message for invalid hosts
	if result == "" {
		t.Log("ProbeONVIF returned empty string for invalid host (expected)")
	} else {
		t.Logf("ProbeONVIF returned: %s", result)
	}
}

func TestRTSPInfo_Empty(t *testing.T) {
	info := RTSPInfo{}
	if info.Any {
		t.Error("Empty RTSPInfo should have Any=false")
	}
	if info.Server != "" {
		t.Error("Empty RTSPInfo should have empty Server")
	}
	if info.Public != "" {
		t.Error("Empty RTSPInfo should have empty Public")
	}
}