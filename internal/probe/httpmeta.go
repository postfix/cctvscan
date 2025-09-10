package probe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/postfix/cctvscan/internal/util"
)

type HTTPMeta struct {
	Server      string
	BodySnippet string
}

// CameraPorts contains all common camera-related ports
var CameraPorts = []int{
	// Web ports
	80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 443, 8080, 8443, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010,
	8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8101, 8102, 8103, 8104,
	// Other web
	7001, 8999, 9000, 9001, 9002, 10000, 8181, 5001, 50000, 8880, 8889, 3001,
	// RTSP
	554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554,
	// RTMP
	1935, 1936, 1937, 1938, 1939,
	// ONVIF/discovery
	3702,
	// Miscellaneous
	37777, 5000,
}

// CameraPaths contains common HTTP paths for cameras
var CameraPaths = []string{
	"/", "/1", "/admin", "/login", "/viewer", "/webadmin", "/video", "/stream", "/live", "/snapshot",
	"/onvif-http/snapshot", "/system.ini", "/config", "/setup", "/cgi-bin/", "/api/", "/camera", "/img/main.cgi",
	"/index.html", "/onvif/device_service", "/onvif/streaming", "/axis-cgi/mjpg/video.cgi", "/axis-cgi/com/ptz.cgi",
	"/axis-cgi/param.cgi", "/cgi-bin/snapshot.cgi", "/cgi-bin/hi3510/snap.cgi", "/videostream.cgi", "/mjpg/video.mjpg",
}

// MJPEGPaths contains paths for MJPEG streams
var MJPEGPaths = []string{
	// Axis
	"/axis-cgi/mjpg/video.cgi",
	// Foscam/D-Link/EasyN
	"/mjpeg.cgi", "/video/mjpg.cgi", "/videostream.cgi",
	// Edimax/Intellinet/TP-Link/Trendnet/Vivotek
	"/mjpg/video.mjpg", "/jpg/image.jpg", "/snapshot.cgi", "/image.jpg", "/cgi-bin/video.jpg", "/cgi-bin/viewer/video.jpg",
	// Panasonic
	"/SnapshotJPEG", "/cgi-bin/nphMotionJpeg",
	// Mobotix
	"/faststream.jpg", "/control/faststream.jpg",
	// Generic
	"/stream.jpg", "/video.jpg", "/liveimg.cgi", "/now.jpg", "/image", "/oneshotimage.jpg",
}

// CameraContentTypes contains content types that indicate camera streams
var CameraContentTypes = []string{
	// Snapshots/MJPEG
	"image/jpeg", "image/jpg", "image/pjpeg", "image/png", "image/gif", "multipart/x-mixed-replace",
	// Videos
	"video/mpeg", "video/mp4", "video/h264", "video/h265", "video/hevc", "video/3gpp", "video/webm", "video/ogg",
	"application/mp4", "application/sdp", "application/vnd.apple.mpegurl", "application/x-mpegURL", "application/octet-stream",
	"video/MP2T", "application/x-rtsp",
	// Miscellaneous
	"text/html", "application/json", "application/xml", "text/xml",
}

func FilterHTTPish(ports []int) []int {
	var out []int
	for _, p := range ports {
		if isHTTPLikePort(p) {
			out = append(out, p)
		}
	}
	return out
}

func ProbeHTTPMeta(ctx context.Context, host string, ports []int) HTTPMeta {
	meta := HTTPMeta{}
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ InsecureSkipVerify: true },
			DisableKeepAlives: true,
			DialContext: (&net.Dialer{ Timeout: 1200 * time.Millisecond }).DialContext,
		},
	}
	for _, p := range ports {
		scheme := "http"
		if isHTTPS(p) { scheme="https" }
		url := scheme + "://" + net.JoinHostPort(host, util.Itoa(p)) + "/"
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("User-Agent", "CCTVTool/1.0")
		resp, err := client.Do(req)
		if err != nil { continue }
		if meta.Server == "" {
			meta.Server = resp.Header.Get("Server")
		}
		if meta.BodySnippet == "" {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			meta.BodySnippet = strings.ToLower(string(b))
		}
		resp.Body.Close()
		if meta.Server!="" && meta.BodySnippet!="" { break }
	}
	return meta
}

func FindLoginPages(ctx context.Context, host string, ports []int) []string {
	paths := []string{"/", "/login", "/admin", "/viewer", "/webadmin", "/index.html"}
	client := &http.Client{
		Timeout: 1500 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ InsecureSkipVerify: true },
			DisableKeepAlives: true,
		},
	}
	var out []string
	for _, p := range ports {
		scheme := "http"; if isHTTPS(p) { scheme="https" }
		base := scheme + "://" + net.JoinHostPort(host, util.Itoa(p))
		for _, path := range paths {
			req, _ := http.NewRequestWithContext(ctx, "HEAD", base+path, nil)
			resp, err := client.Do(req)
			if err != nil { continue }
			resp.Body.Close()
			if resp.StatusCode == 200 {
				out = append(out, base+path)
			}
			if resp.StatusCode==401 || resp.StatusCode==403 || resp.Header.Get("WWW-Authenticate")!="" {
				out = append(out, base+path)
			}
		}
	}
	return util.Uniq(out)
}

func isHTTPS(p int) bool { switch p{ case 443, 8443: return true }; return false }

func isHTTPLikePort(p int) bool {
	// ports explicitly NON-HTTP
	switch p {
	case 554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554: // RTSP
		return false
	case 1935, 1936, 1937, 1938, 1939: // RTMP
		return false
	case 3702, 37777: // ONVIF discovery + proprietary DVR
		return false
	}
	// all others (web/http-like) → keep
	return true
}

// CameraPortsString returns a naabu-compatible port string for all camera ports
func CameraPortsString() string {
	portSet := make(map[int]bool)
	for _, port := range CameraPorts {
		portSet[port] = true
	}
	
	// Convert to slice and sort for consistent output
	uniquePorts := make([]int, 0, len(portSet))
	for port := range portSet {
		uniquePorts = append(uniquePorts, port)
	}
	
	// Simple implementation - just join with commas for now
	// Naabu can handle up to 1000 ports in a single command
	if len(uniquePorts) <= 1000 {
		return intSliceToString(uniquePorts)
	}
	
	// For large port sets, use ranges (but our camera ports are only 79)
	return intSliceToString(uniquePorts)
}

// intSliceToString converts a slice of integers to a comma-separated string
func intSliceToString(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	
	var sb strings.Builder
	sb.WriteString(util.Itoa(ports[0]))
	for i := 1; i < len(ports); i++ {
		sb.WriteString(",")
		sb.WriteString(util.Itoa(ports[i]))
	}
	return sb.String()
}

