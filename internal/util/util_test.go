package util

import "testing"

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{123, "123"},
		{-456, "-456"},
		{65535, "65535"},
	}

	for _, test := range tests {
		result := Itoa(test.input)
		if result != test.expected {
			t.Errorf("Itoa(%d) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

func TestUniq(t *testing.T) {
	tests := []struct {
		input    []string
		expected []string
	}{
		{[]string{"a", "b", "a"}, []string{"a", "b"}},
		{[]string{"1", "2", "3"}, []string{"1", "2", "3"}},
		{[]string{}, []string{}},
		{[]string{"x", "x", "x"}, []string{"x"}},
	}

	for _, test := range tests {
		result := Uniq(test.input)
		if len(result) != len(test.expected) {
			t.Errorf("Uniq(%v) length = %d, expected %d", test.input, len(result), len(test.expected))
		}
		for i := range result {
			if result[i] != test.expected[i] {
				t.Errorf("Uniq(%v)[%d] = %s, expected %s", test.input, i, result[i], test.expected[i])
			}
		}
	}
}

func BenchmarkPortIn_SortedLarge(b *testing.B) {
	ports := make([]int, 1000)
	for i := 0; i < 1000; i++ {
		ports[i] = i * 2 // Even numbers, sorted
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PortIn(ports, 500)
	}
}

func BenchmarkPortIn_UnsortedLarge(b *testing.B) {
	ports := make([]int, 1000)
	for i := 0; i < 1000; i++ {
		ports[i] = (i * 7) % 1000 // Unsorted pattern
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PortIn(ports, 500)
	}
}

func BenchmarkPortIn_Small(b *testing.B) {
	ports := []int{80, 443, 8080, 8443}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		PortIn(ports, 443)
	}
}

func TestPortIn(t *testing.T) {
	tests := []struct {
		ports    []int
		port     int
		expected bool
	}{
		{[]int{80, 443, 8080}, 80, true},
		{[]int{80, 443, 8080}, 8080, true},
		{[]int{80, 443, 8080}, 22, false},
		{[]int{}, 80, false},
		{[]int{443}, 443, true},
	}

	for _, test := range tests {
		result := PortIn(test.ports, test.port)
		if result != test.expected {
			t.Errorf("PortIn(%v, %d) = %t, expected %t", test.ports, test.port, result, test.expected)
		}
	}
}