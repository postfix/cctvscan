package streams

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// StreamType represents different types of camera streams
type StreamType string

const (
	StreamMJPEG   StreamType = "MJPEG"
	StreamRTSP    StreamType = "RTSP"
	StreamRTMP    StreamType = "RTMP"
	StreamMMS     StreamType = "MMS"
	StreamHLS     StreamType = "HLS"
	StreamGeneric StreamType = "Generic"
)

// StreamResult contains information about detected streams
type StreamResult struct {
	URL         string
	Type        StreamType
	ContentType string
	Status      int
	Size        int64
	Path        string
}

// Comprehensive stream paths for different camera brands and protocols
var StreamPaths = map[string][]string{
	"rtsp": {
		// Generic RTSP paths
		"/live.sdp",
		"/h264.sdp",
		"/stream1",
		"/stream2",
		"/main",
		"/sub",
		"/video",
		"/cam/realmonitor",
		"/Streaming/Channels/1",
		"/Streaming/Channels/101",
		// Brand-specific RTSP paths
		"/onvif/streaming/channels/1", // ONVIF
		"/live/0/onvif.sdp",           // ONVIF
		"/live/0/h264.sdp",            // Generic
		"/live/0/mpeg4.sdp",           // Generic
		"/live/0/audio.sdp",           // Generic
		"/live/1/onvif.sdp",           // ONVIF
		"/live/1/h264.sdp",            // Generic
		"/live/1/mpeg4.sdp",           // Generic
		"/live/1/audio.sdp",           // Generic
	},
	"rtmp": {
		"/live",
		"/stream",
		"/hls",
		"/flv",
		"/rtmp",
		"/live/stream",
		"/live/stream1",
		"/live/stream2",
		"/live/main",
		"/live/sub",
		"/live/video",
		"/live/audio",
		"/live/av",
		"/live/rtmp",
		"/live/rtmps",
	},
	"http": {
		// Generic HTTP stream paths
		"/video",
		"/stream",
		"/mjpg/video.mjpg",
		"/cgi-bin/mjpg/video.cgi",
		"/axis-cgi/mjpg/video.cgi",
		"/cgi-bin/viewer/video.jpg",
		"/snapshot.jpg",
		"/img/snapshot.cgi",
		// Brand-specific HTTP paths
		"/onvif/device_service",     // ONVIF
		"/onvif/streaming",          // ONVIF
		"/axis-cgi/com/ptz.cgi",     // Axis
		"/axis-cgi/param.cgi",       // Axis
		"/cgi-bin/snapshot.cgi",     // Generic
		"/cgi-bin/hi3510/snap.cgi",  // Hikvision
		"/cgi-bin/viewer/video.jpg", // Generic
		"/img/snapshot.cgi",         // Generic
		"/snapshot.jpg",             // Generic
		"/video/mjpg.cgi",           // Generic
		"/video.cgi",                // Generic
		"/videostream.cgi",          // Generic
		"/mjpg/video.mjpg",          // Generic
		"/mjpg.cgi",                 // Generic
		"/stream.cgi",               // Generic
		"/live.cgi",                 // Generic
		// Additional API endpoints
		"/api/video", // API endpoints
		"/api/stream",
		"/api/live",
		"/api/video/live",
		"/api/stream/live",
		"/api/camera/live",
		"/api/camera/stream",
		"/api/camera/video",
		"/api/camera/snapshot",
		"/api/camera/image",
		"/api/camera/feed",
		"/api/camera/feed/live",
		"/api/camera/feed/stream",
		"/api/camera/feed/video",
		// CP Plus specific paths
		"/cgi-bin/snapshot.cgi",
		"/cgi-bin/video.cgi",
		"/cgi-bin/stream.cgi",
		"/cgi-bin/live.cgi",
	},
}

// Streaming ports by protocol
var StreamingPorts = map[string][]int{
	"rtsp":  {554, 8554, 10554},
	"rtmp":  {1935, 1936},
	"http":  {80, 8080, 8000, 8001},
	"https": {443, 8443, 8444},
	"mms":   {1755},
	"onvif": {3702, 80, 443},
	"vlc":   {8080, 8090},
}

// Camera content types for stream detection
var StreamContentTypes = []string{
	"image/jpeg", "image/jpg", "image/pjpeg", "image/png", "image/gif",
	"multipart/x-mixed-replace",
	"video/mpeg", "video/mp4", "video/h264", "video/h265", "video/hevc",
	"video/3gpp", "video/webm", "video/ogg", "video/MP2T",
	"application/mp4", "application/sdp", "application/vnd.apple.mpegurl",
	"application/x-mpegURL", "application/octet-stream", "application/x-rtsp",
	"text/html", "application/json", "application/xml", "text/xml",
}

// Video file extensions
var VideoExtensions = []string{
	".mp4", ".m3u8", ".ts", ".flv", ".webm", ".avi", ".mov",
}

// Streaming protocol prefixes
var StreamingProtocols = []string{
	"rtsp://", "rtmp://", "mms://", "rtp://",
}

// DetectStreams performs comprehensive stream detection
func DetectStreams(ctx context.Context, host string, ports []int, outDir string) []StreamResult {
	_ = os.MkdirAll(outDir, 0o755)
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext,
		},
	}

	var results []StreamResult

	for _, port := range ports {
		// Determine protocol
		protocol := "http"
		if port == 443 || port == 8443 || port == 8444 {
			protocol = "https"
		}

		baseURL := fmt.Sprintf("%s://%s:%d", protocol, host, port)

		// Check for streams based on port type
		if isRTSPPort(port) {
			results = append(results, checkRTSPStreams(ctx, host, port)...)
		} else if isRTMPPort(port) {
			results = append(results, checkRTMPStreams(ctx, host, port)...)
		} else if isMMSPort(port) {
			results = append(results, checkMMSStreams(ctx, host, port)...)
		} else {
			// Check HTTP/HTTPS streams
			results = append(results, checkHTTPStreams(ctx, client, baseURL, port)...)
		}
	}

	// Save stream snapshots
	for _, result := range results {
		if result.Type == StreamMJPEG || result.Type == StreamGeneric {
			saveStreamSnapshot(ctx, client, result, outDir)
		}
	}

	return results
}

// checkHTTPStreams checks for HTTP/HTTPS based streams
func checkHTTPStreams(ctx context.Context, client *http.Client, baseURL string, port int) []StreamResult {
	var results []StreamResult

	// Check all HTTP stream paths
	for _, path := range StreamPaths["http"] {
		url := baseURL + path
		result := checkStreamURL(ctx, client, url, port, path)
		if result != nil {
			results = append(results, *result)
		}
	}

	return results
}

// checkRTSPStreams checks for RTSP streams
func checkRTSPStreams(ctx context.Context, host string, port int) []StreamResult {
	var results []StreamResult

	for _, path := range StreamPaths["rtsp"] {
		url := fmt.Sprintf("rtsp://%s:%d%s", host, port, path)
		// For RTSP, we can't easily check with HTTP client
		// This would require RTSP client implementation
		// For now, we'll add it as a potential stream
		results = append(results, StreamResult{
			URL:         url,
			Type:        StreamRTSP,
			ContentType: "application/sdp",
			Status:      200, // Assume available
			Path:        path,
		})
	}

	return results
}

// checkRTMPStreams checks for RTMP streams
func checkRTMPStreams(ctx context.Context, host string, port int) []StreamResult {
	var results []StreamResult

	for _, path := range StreamPaths["rtmp"] {
		url := fmt.Sprintf("rtmp://%s:%d%s", host, port, path)
		// RTMP detection would require RTMP client
		// For now, add as potential stream
		results = append(results, StreamResult{
			URL:         url,
			Type:        StreamRTMP,
			ContentType: "application/x-rtmp",
			Status:      200,
			Path:        path,
		})
	}

	return results
}

// checkMMSStreams checks for MMS streams
func checkMMSStreams(ctx context.Context, host string, port int) []StreamResult {
	var results []StreamResult

	url := fmt.Sprintf("mms://%s:%d", host, port)
	results = append(results, StreamResult{
		URL:         url,
		Type:        StreamMMS,
		ContentType: "application/x-mms",
		Status:      200,
		Path:        "/",
	})

	return results
}

// checkStreamURL checks a specific URL for stream content
func checkStreamURL(ctx context.Context, client *http.Client, url string, port int, path string) *StreamResult {
	// Method 1: Try HEAD request first
	req, _ := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	req.Header.Set("User-Agent", "CCTVTool/1.0")
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == 200 {
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		if isStreamContentType(contentType) || isStreamURL(url) {
			resp.Body.Close()
			return &StreamResult{
				URL:         url,
				Type:        determineStreamType(contentType, url),
				ContentType: contentType,
				Status:      resp.StatusCode,
				Path:        path,
			}
		}
		resp.Body.Close()
	}

	// Method 2: Try GET request for better detection
	req, _ = http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "CCTVTool/1.0")
	resp, err = client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))

		// Check content type
		if isStreamContentType(contentType) {
			return &StreamResult{
				URL:         url,
				Type:        determineStreamType(contentType, url),
				ContentType: contentType,
				Status:      resp.StatusCode,
				Path:        path,
			}
		}

		// Check URL patterns
		if isStreamURL(url) {
			return &StreamResult{
				URL:         url,
				Type:        determineStreamType(contentType, url),
				ContentType: contentType,
				Status:      resp.StatusCode,
				Path:        path,
			}
		}

		// Check response content for stream indicators
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
		if err == nil {
			content := strings.ToLower(string(body))
			if containsStreamKeywords(content) {
				return &StreamResult{
					URL:         url,
					Type:        StreamGeneric,
					ContentType: contentType,
					Status:      resp.StatusCode,
					Path:        path,
				}
			}
		}
	}

	return nil
}

// Helper functions
func isRTSPPort(port int) bool {
	for _, p := range StreamingPorts["rtsp"] {
		if port == p {
			return true
		}
	}
	return false
}

func isRTMPPort(port int) bool {
	for _, p := range StreamingPorts["rtmp"] {
		if port == p {
			return true
		}
	}
	return false
}

func isMMSPort(port int) bool {
	for _, p := range StreamingPorts["mms"] {
		if port == p {
			return true
		}
	}
	return false
}

func isStreamContentType(contentType string) bool {
	for _, ct := range StreamContentTypes {
		if strings.Contains(contentType, ct) {
			return true
		}
	}
	return false
}

func isStreamURL(url string) bool {
	urlLower := strings.ToLower(url)

	// Check for video file extensions
	for _, ext := range VideoExtensions {
		if strings.Contains(urlLower, ext) {
			return true
		}
	}

	// Check for streaming protocols
	for _, protocol := range StreamingProtocols {
		if strings.Contains(urlLower, protocol) {
			return true
		}
	}

	// Check for stream path patterns
	streamPaths := []string{"/video", "/stream", "/live", "/mjpg", "/snapshot"}
	for _, path := range streamPaths {
		if strings.Contains(urlLower, path) {
			return true
		}
	}

	return false
}

func containsStreamKeywords(content string) bool {
	keywords := []string{"stream", "video", "live", "camera", "mjpg", "mpeg"}
	for _, keyword := range keywords {
		if strings.Contains(content, keyword) {
			return true
		}
	}
	return false
}

func determineStreamType(contentType, url string) StreamType {
	urlLower := strings.ToLower(url)
	contentTypeLower := strings.ToLower(contentType)

	if strings.Contains(urlLower, "rtsp://") {
		return StreamRTSP
	}
	if strings.Contains(urlLower, "rtmp://") {
		return StreamRTMP
	}
	if strings.Contains(urlLower, "mms://") {
		return StreamMMS
	}
	if strings.Contains(contentTypeLower, "multipart/x-mixed-replace") ||
		strings.Contains(contentTypeLower, "image/jpeg") {
		return StreamMJPEG
	}
	if strings.Contains(contentTypeLower, "video/") {
		return StreamGeneric
	}

	return StreamGeneric
}

func saveStreamSnapshot(ctx context.Context, client *http.Client, result StreamResult, outDir string) {
	req, _ := http.NewRequestWithContext(ctx, "GET", result.URL, nil)
	req.Header.Set("User-Agent", "CCTVTool/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		// Save up to first 256KB
		filename := fmt.Sprintf("%s_%d_%s.jpg",
			strings.ReplaceAll(result.URL, "://", "_"),
			result.Status,
			sanitizePath(result.Path))
		filepath := filepath.Join(outDir, filename)

		f, err := os.Create(filepath)
		if err != nil {
			return
		}
		defer f.Close()

		io.CopyN(f, resp.Body, 256*1024)
	}
}

func sanitizePath(path string) string {
	replacer := strings.NewReplacer("/", "_", "?", "_", "&", "_", "=", "_")
	return replacer.Replace(path)
}
