package processor

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func BenchmarkOptimizedProcessor(b *testing.B) {
	processor := NewOptimizedProcessor(false, "", "/tmp")

	// Test data
	results := map[string][]int{
		"192.168.1.1": {80, 443, 8080},
		"192.168.1.2": {80, 554, 8080},
		"192.168.1.3": {443, 8443},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessHosts(ctx, results)
	}
}

func BenchmarkHostProcessing(b *testing.B) {
	processor := NewOptimizedProcessor(false, "", "/tmp")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ports := []int{80, 443, 8080, 554, 8443}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.processHost(ctx, "192.168.1.1", ports)
	}
}

func BenchmarkConcurrentProcessing(b *testing.B) {
	processor := NewOptimizedProcessor(false, "", "/tmp")

	// Create more test data for concurrent processing
	results := make(map[string][]int)
	for i := 0; i < 10; i++ {
		host := fmt.Sprintf("192.168.1.%d", i+1)
		results[host] = []int{80, 443, 8080}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.ProcessHosts(ctx, results)
	}
}
