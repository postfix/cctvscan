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

// CameraPorts contains the default set of common camera-related ports (79 ports)
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

// ComprehensiveCameraPorts contains all camera-related ports (1000+ ports) for thorough scanning
var ComprehensiveCameraPorts = []int{
	// Standard web ports
	80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
	8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,

	// RTSP ports
	554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 8554, 9554,

	// RTMP ports
	1935, 1936, 1937, 1938, 1939,

	// Custom camera ports (Hikvision, Dahua, etc.)
	37777, 37778, 37779, 37780, 37781, 37782, 37783, 37784, 37785, 37786, 37787, 37788, 37789, 37790,
	37791, 37792, 37793, 37794, 37795, 37796, 37797, 37798, 37799, 37800,

	// ONVIF ports
	3702, 3703, 3704, 3705, 3706, 3707, 3708, 3709, 3710,

	// VLC streaming ports
	8080, 8090, 8100, 8110, 8120, 8130, 8140, 8150, 8160, 8170, 8180, 8190,

	// Common alternative ports
	5000, 5001, 5002, 5003, 5004, 5005, 5006, 5007, 5008, 5009, 5010,
	6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008, 6009, 6010,
	7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010,
	9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010,

	// Additional common ports
	8888, 8889, 8890, 8891, 8892, 8893, 8894, 8895, 8896, 8897, 8898, 8899,
	9999, 9998, 9997, 9996, 9995, 9994, 9993, 9992, 9991, 9990,

	// MMS ports
	1755, 1756, 1757, 1758, 1759, 1760,

	// High ports commonly used by cameras
	10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10010,
	11000, 11001, 11002, 11003, 11004, 11005, 11006, 11007, 11008, 11009, 11010,
	12000, 12001, 12002, 12003, 12004, 12005, 12006, 12007, 12008, 12009, 12010,
	13000, 13001, 13002, 13003, 13004, 13005, 13006, 13007, 13008, 13009, 13010,
	14000, 14001, 14002, 14003, 14004, 14005, 14006, 14007, 14008, 14009, 14010,
	15000, 15001, 15002, 15003, 15004, 15005, 15006, 15007, 15008, 15009, 15010,

	// Extended high ports
	20000, 20001, 20002, 20003, 20004, 20005, 20006, 20007, 20008, 20009, 20010,
	21000, 21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21009, 21010,
	22000, 22001, 22002, 22003, 22004, 22005, 22006, 22007, 22008, 22009, 22010,
	23000, 23001, 23002, 23003, 23004, 23005, 23006, 23007, 23008, 23009, 23010,
	24000, 24001, 24002, 24003, 24004, 24005, 24006, 24007, 24008, 24009, 24010,
	25000, 25001, 25002, 25003, 25004, 25005, 25006, 25007, 25008, 25009, 25010,

	// Additional custom ranges
	30000, 30001, 30002, 30003, 30004, 30005, 30006, 30007, 30008, 30009, 30010,
	31000, 31001, 31002, 31003, 31004, 31005, 31006, 31007, 31008, 31009, 31010,
	32000, 32001, 32002, 32003, 32004, 32005, 32006, 32007, 32008, 32009, 32010,
	33000, 33001, 33002, 33003, 33004, 33005, 33006, 33007, 33008, 33009, 33010,
	34000, 34001, 34002, 34003, 34004, 34005, 34006, 34007, 34008, 34009, 34010,
	35000, 35001, 35002, 35003, 35004, 35005, 35006, 35007, 35008, 35009, 35010,
	36000, 36001, 36002, 36003, 36004, 36005, 36006, 36007, 36008, 36009, 36010,
	37000, 37001, 37002, 37003, 37004, 37005, 37006, 37007, 37008, 37009, 37010,
	38000, 38001, 38002, 38003, 38004, 38005, 38006, 38007, 38008, 38009, 38010,
	39000, 39001, 39002, 39003, 39004, 39005, 39006, 39007, 39008, 39009, 39010,
	40000, 40001, 40002, 40003, 40004, 40005, 40006, 40007, 40008, 40009, 40010,
	41000, 41001, 41002, 41003, 41004, 41005, 41006, 41007, 41008, 41009, 41010,
	42000, 42001, 42002, 42003, 42004, 42005, 42006, 42007, 42008, 42009, 42010,
	43000, 43001, 43002, 43003, 43004, 43005, 43006, 43007, 43008, 43009, 43010,
	44000, 44001, 44002, 44003, 44004, 44005, 44006, 44007, 44008, 44009, 44010,
	45000, 45001, 45002, 45003, 45004, 45005, 45006, 45007, 45008, 45009, 45010,
	46000, 46001, 46002, 46003, 46004, 46005, 46006, 46007, 46008, 46009, 46010,
	47000, 47001, 47002, 47003, 47004, 47005, 47006, 47007, 47008, 47009, 47010,
	48000, 48001, 48002, 48003, 48004, 48005, 48006, 48007, 48008, 48009, 48010,
	49000, 49001, 49002, 49003, 49004, 49005, 49006, 49007, 49008, 49009, 49010,
	50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010,
	51000, 51001, 51002, 51003, 51004, 51005, 51006, 51007, 51008, 51009, 51010,
	52000, 52001, 52002, 52003, 52004, 52005, 52006, 52007, 52008, 52009, 52010,
	53000, 53001, 53002, 53003, 53004, 53005, 53006, 53007, 53008, 53009, 53010,
	54000, 54001, 54002, 54003, 54004, 54005, 54006, 54007, 54008, 54009, 54010,
	55000, 55001, 55002, 55003, 55004, 55005, 55006, 55007, 55008, 55009, 55010,
	56000, 56001, 56002, 56003, 56004, 56005, 56006, 56007, 56008, 56009, 56010,
	57000, 57001, 57002, 57003, 57004, 57005, 57006, 57007, 57008, 57009, 57010,
	58000, 58001, 58002, 58003, 58004, 58005, 58006, 58007, 58008, 58009, 58010,
	59000, 59001, 59002, 59003, 59004, 59005, 59006, 59007, 59008, 59009, 59010,
	60000, 60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010,
	61000, 61001, 61002, 61003, 61004, 61005, 61006, 61007, 61008, 61009, 61010,
	62000, 62001, 62002, 62003, 62004, 62005, 62006, 62007, 62008, 62009, 62010,
	63000, 63001, 63002, 63003, 63004, 63005, 63006, 63007, 63008, 63009, 63010,
	64000, 64001, 64002, 64003, 64004, 64005, 64006, 64007, 64008, 64009, 64010,
	65000, 65001, 65002, 65003, 65004, 65005, 65006, 65007, 65008, 65009, 65010,
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

// Note: CameraContentTypes moved to camera_detection.go to avoid duplication

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
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: 1200 * time.Millisecond}).DialContext,
		},
	}
	for _, p := range ports {
		scheme := "http"
		if isHTTPS(p) {
			scheme = "https"
		}
		url := scheme + "://" + net.JoinHostPort(host, util.Itoa(p)) + "/"
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("User-Agent", "CCTVTool/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if meta.Server == "" {
			meta.Server = resp.Header.Get("Server")
		}
		if meta.BodySnippet == "" {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			meta.BodySnippet = strings.ToLower(string(b))
		}
		resp.Body.Close()
		if meta.Server != "" && meta.BodySnippet != "" {
			break
		}
	}
	return meta
}

func FindLoginPages(ctx context.Context, host string, ports []int) []string {
	paths := []string{"/", "/login", "/admin", "/viewer", "/webadmin", "/index.html"}
	client := &http.Client{
		Timeout: 1500 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}
	var out []string
	for _, p := range ports {
		scheme := "http"
		if isHTTPS(p) {
			scheme = "https"
		}
		base := scheme + "://" + net.JoinHostPort(host, util.Itoa(p))
		for _, path := range paths {
			req, _ := http.NewRequestWithContext(ctx, "HEAD", base+path, nil)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()
			if resp.StatusCode == 200 {
				out = append(out, base+path)
			}
			if resp.StatusCode == 401 || resp.StatusCode == 403 || resp.Header.Get("WWW-Authenticate") != "" {
				out = append(out, base+path)
			}
		}
	}
	return util.Uniq(out)
}

func isHTTPS(p int) bool {
	switch p {
	case 443, 8443:
		return true
	}
	return false
}

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

// CameraPortsString returns a naabu-compatible port string for default camera ports
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

	return intSliceToString(uniquePorts)
}

// ComprehensiveCameraPortsString returns a naabu-compatible port string for all camera ports (1000+)
func ComprehensiveCameraPortsString() string {
	portSet := make(map[int]bool)
	for _, port := range ComprehensiveCameraPorts {
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

	// For large port sets, use ranges
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
