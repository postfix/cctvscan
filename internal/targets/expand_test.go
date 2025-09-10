package targets

import "testing"

func TestFromArgsOrFileCIDR(t *testing.T) {
	got, err := FromArgsOrFile([]string{"192.0.2.0/30"}, "")
	if err != nil { t.Fatal(err) }
	if len(got) != 4 { t.Fatalf("want 4, got %d", len(got)) }
}

