package report

import "testing"

func TestJSON(t *testing.T) {
	tr := TargetResult{Host:"1.2.3.4", OpenPorts: []int{80,554}}
	if len(tr.JSON())==0 { t.Fatal("want json") }
}

