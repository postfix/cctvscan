package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/postfix/cctvscan/internal/util"
)

type RTSPInfo struct {
	Any    bool
	Server string
	Public string
}

func FilterRTSP(ports []int) []int {
	var out []int
	for _, p := range ports {
		switch p {
		case 554, 8554, 10554, 1554, 2554, 3554, 4554, 5554, 6554, 7554, 9554:
			out = append(out, p)
		}
	}
	return out
}

func ProbeRTSP(ctx context.Context, host string, ports []int) RTSPInfo {
	var info RTSPInfo
	for _, p := range ports {
		addr := net.JoinHostPort(host, util.Itoa(p))
		c, err := net.DialTimeout("tcp", addr, 1200*time.Millisecond)
		if err != nil { continue }
		_ = c.SetDeadline(time.Now().Add(1500*time.Millisecond))
		fmt.Fprintf(c, "OPTIONS rtsp://%s RTSP/1.0\r\nCSeq: 1\r\n\r\n", addr)
		br := bufio.NewReader(c)
		status, _ := br.ReadString('\n')
		if strings.HasPrefix(status, "RTSP/1.0 200") {
			info.Any = true
			// read headers
			for {
				line, _ := br.ReadString('\n')
				line = strings.TrimSpace(line)
				if line == "" { break }
				l := strings.ToLower(line)
				if strings.HasPrefix(l, "server:") && info.Server=="" {
					info.Server = strings.TrimSpace(line[7:])
				}
				if strings.HasPrefix(l, "public:") && info.Public=="" {
					info.Public = strings.TrimSpace(line[7:])
				}
			}
		}
		c.Close()
		if info.Any { break }
	}
	return info
}

// RTSPPaths contains common RTSP stream paths
var RTSPPaths = []string{
	"/live", "/live.sdp", "/h264", "/h264.sdp", "/mpeg4", "/stream1", "/stream2", "/main", "/sub", "/1",
	"/ch0_0.264", "/Streaming/Channels/1", "/Streaming/Channels/101", "/onvif/streaming/channels/1",
	"/axis-media/media.amp", "/cam/realmonitor?channel=1&subtype=0",
}

// RTSPCommands contains RTSP commands for capability detection
var RTSPCommands = []string{
	"OPTIONS", "DESCRIBE", "PLAY", "PAUSE", "SETUP", "TEARDOWN", "SET_PARAMETER", "GET_PARAMETER",
}

// ProbeRTSPDescribe performs DESCRIBE request to validate RTSP streams
func ProbeRTSPDescribe(ctx context.Context, host string, port int, path string) (int, bool, error) {
	addr := net.JoinHostPort(host, util.Itoa(port))
	c, err := net.DialTimeout("tcp", addr, 1000*time.Millisecond)
	if err != nil {
		return -1, false, err
	}
	defer c.Close()
	
	_ = c.SetDeadline(time.Now().Add(2000*time.Millisecond))
	
	url := "rtsp://" + addr + path
	fmt.Fprintf(c, "DESCRIBE %s RTSP/1.0\r\nCSeq: 2\r\nUser-Agent: CCTVScan/1.0\r\nAccept: application/sdp\r\n\r\n", url)
	
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		return -1, false, err
	}
	
	var codeOut int = -1
	if strings.HasPrefix(status, "RTSP/1.0 ") {
		parts := strings.Split(status, " ")
		if len(parts) >= 2 {
			codeOut = util.Atoi(parts[1])
		}
	}
	
	// Read headers
	var contentType string
	var contentLength int = -1
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		line = strings.TrimSpace(line)
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "content-type:") {
			contentType = strings.TrimSpace(line[13:])
		}
		if strings.HasPrefix(low, "content-length:") {
			contentLength = util.Atoi(strings.TrimSpace(line[15:]))
		}
	}
	
	// Read partial body to validate SDP
	var body []byte
	if contentLength > 0 {
		body = make([]byte, min(contentLength, 2048))
		_, err = io.ReadFull(br, body)
	} else {
		// Read what we can get in reasonable time
		body, _ = io.ReadAll(io.LimitReader(br, 2048))
	}
	
	// Validate SDP content
	bodyStr := string(body)
	headerSdp := strings.Contains(strings.ToLower(contentType), "application/sdp") || strings.Contains(contentType, "/sdp")
	looksSdp := strings.Contains(bodyStr, "v=0") && strings.Contains(bodyStr, "m=video")
	
	return codeOut, (headerSdp && looksSdp), nil
}



