// Package util provides shared utility functions for the cctvscan project.
// It includes common operations like string conversion, deduplication, and port checking.
package util

import "strconv"

// Itoa converts an integer to string using strconv.Itoa.
// This provides a consistent interface for integer-to-string conversion.
func Itoa(i int) string { return strconv.Itoa(i) }

// Atoi converts a string to integer using strconv.Atoi.
// Returns 0 if conversion fails.
func Atoi(s string) int {
	if i, err := strconv.Atoi(s); err == nil {
		return i
	}
	return 0
}

// Uniq removes duplicates from a string slice while preserving order.
// It uses a map to track seen elements and returns a new slice with unique values.
func Uniq(in []string) []string {
	m := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := m[s]; !ok { m[s] = struct{}{}; out = append(out, s) }
	}
	return out
}

// PortIn checks if a port exists in a slice of ports.
// Returns true if the port is found, false otherwise.
// Uses binary search for sorted slices, linear search for small/unsorted ones.
func PortIn(ports []int, p int) bool {
	// Use binary search if slice is sorted and large enough
	if len(ports) > 10 && isSorted(ports) {
		left, right := 0, len(ports)-1
		for left <= right {
			mid := left + (right-left)/2
			if ports[mid] == p {
				return true
			}
			if ports[mid] < p {
				left = mid + 1
			} else {
				right = mid - 1
			}
		}
		return false
	}
	
	// Linear search for small or unsorted slices
	for _, x := range ports { if x == p { return true } }
	return false
}

// isSorted checks if a slice of integers is sorted in ascending order
func isSorted(ports []int) bool {
	for i := 1; i < len(ports); i++ {
		if ports[i] < ports[i-1] {
			return false
		}
	}
	return true
}