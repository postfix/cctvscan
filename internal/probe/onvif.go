package probe

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Minimal unicast WS-Discovery probe to UDP 3702.
// Returns a short description if any response is received.
func ProbeONVIF(ctx context.Context, host string) string {
	addr := net.JoinHostPort(host, "3702")
	c, err := net.DialTimeout("udp", addr, 800*time.Millisecond)
	if err != nil { return "" }
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(1200*time.Millisecond))
	// very small SOAP Probe (trimmed)
	body := `<?xml version="1.0"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
 <e:Header>
  <w:MessageID>uuid:00000000-0000-0000-0000-000000000000</w:MessageID>
  <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
  <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
 </e:Header>
 <e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>
</e:Envelope>`
	if _, err := c.Write([]byte(body)); err != nil {
		return fmt.Sprintf("write error: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil {
		return fmt.Sprintf("read error: %v", err)
	}
	if n > 0 { return fmt.Sprintf("response %dB", n) }
	return ""
}
