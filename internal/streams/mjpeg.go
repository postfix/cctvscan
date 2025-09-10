package streams

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var snapshotPaths = []string{
	"/snapshot", "/jpg/image.jpg", "/image.jpg", "/snapshot.cgi",
	"/cgi-bin/snapshot.cgi", "/mjpg/video.mjpg",
}

func TryMJPEG(ctx context.Context, host string, ports []int, outDir string) {
	_ = os.MkdirAll(outDir, 0o755)
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ InsecureSkipVerify: true },
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{ Timeout: 1200*time.Millisecond }).DialContext,
		},
	}
	for _, p := range ports {
		scheme := "http"; if p==443 || p==8443 { scheme="https" }
		base := scheme + "://" + net.JoinHostPort(host, itoa(p))
		for _, path := range snapshotPaths {
			req, _ := http.NewRequestWithContext(ctx, "GET", base+path, nil)
			resp, err := client.Do(req)
			if err != nil { continue }
			ct := strings.ToLower(resp.Header.Get("Content-Type"))
			if resp.StatusCode==200 && (strings.Contains(ct,"image/jpeg") || strings.Contains(ct,"multipart/x-mixed-replace")) {
				// save up to first 256KB
				name := filepath.Join(outDir, host+"_"+itoa(p)+sanitize(path)+".jpg")
				f, _ := os.Create(name)
				io.CopyN(f, resp.Body, 256*1024)
				f.Close()
				resp.Body.Close()
				return
			}
			resp.Body.Close()
		}
	}
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "_", "?", "_", "&", "_", "=", "_")
	return r.Replace(s)
}
func itoa(i int) string { return fmtInt(int64(i)) }
func fmtInt(i int64) string { if i==0 { return "0" }; var b [20]byte; n:=len(b); for i>0 { n--; b[n]=byte('0'+i%10); i/=10 }; return string(b[n:]) }

