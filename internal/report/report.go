package report

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"
)

type TargetResult struct {
	Host         string   `json:"host"`
	OpenPorts    []int    `json:"open_ports"`
	ServerHeader string   `json:"server_header,omitempty"`
	LoginPages   []string `json:"login_pages,omitempty"`
	Brand        string   `json:"brand,omitempty"`
	CVEs         []string `json:"cves,omitempty"`
	CVELinks     []string `json:"cve_links,omitempty"`
	FoundCred    string   `json:"found_cred,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

func WriteMarkdown(path string, results []TargetResult) error {
	var b bytes.Buffer
	b.WriteString("# CCTV Toolkit Report\n\n")
	sort.Slice(results, func(i, j int) bool { return results[i].Host < results[j].Host })
	for _, r := range results {
		b.WriteString("## " + r.Host + "\n\n")
		if len(r.OpenPorts) > 0 {
			b.WriteString("Open ports: " + intsToCSV(r.OpenPorts) + "\n\n")
		}
		if r.ServerHeader != "" {
			b.WriteString("Server: " + r.ServerHeader + "\n\n")
		}
		if r.Brand != "" {
			b.WriteString("Brand: " + r.Brand + "\n\n")
		}
		if len(r.CVEs) > 0 {
			b.WriteString("CVEs:\n")
			for i := range r.CVEs {
				b.WriteString("- " + r.CVEs[i])
				if i < len(r.CVELinks) { b.WriteString("  (" + r.CVELinks[i] + ")") }
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
		if len(r.LoginPages) > 0 {
			b.WriteString("Login pages:\n")
			for _, u := range r.LoginPages { b.WriteString("- " + u + "\n") }
			b.WriteString("\n")
		}
		if r.FoundCred != "" {
			b.WriteString("Default credential found: `" + r.FoundCred + "`\n\n")
		}
		if len(r.Notes) > 0 {
			b.WriteString("Notes:\n")
			for _, n := range r.Notes { b.WriteString("- " + n + "\n") }
			b.WriteString("\n")
		}
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}

func intsToCSV(in []int) string {
	var sb strings.Builder
	for i, v := range in {
		if i>0 { sb.WriteByte(',') }
		sb.WriteString(fmtInt(int64(v)))
	}
	return sb.String()
}

func (tr TargetResult) JSON() []byte { j,_ := json.Marshal(tr); return j }

func fmtInt(i int64) string {
	if i==0 { return "0" }
	var b [20]byte; n := len(b); for i>0 { n--; b[n]=byte('0'+i%10); i/=10 }
	return string(b[n:])
}

