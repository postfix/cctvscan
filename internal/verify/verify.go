package verify

import (
	"context"
	"net"
	"sort"
	"time"
)

type TCPVerifier struct {
	timeout time.Duration
	retries int
}

func NewTCPVerifier(timeout time.Duration, retries int) *TCPVerifier {
	return &TCPVerifier{timeout: timeout, retries: retries}
}

func (v *TCPVerifier) Verify(ctx context.Context, host string, ports []int) []int {
	var ok []int
	for _, p := range ports {
		addr := net.JoinHostPort(host, itoa(p))
		if v.try(ctx, addr) { ok = append(ok, p) }
	}
	sort.Ints(ok)
	return ok
}

func (v *TCPVerifier) VerifyMap(ctx context.Context, in map[string][]int) map[string][]int {
	out := make(map[string][]int, len(in))
	for h, ps := range in {
		if res := v.Verify(ctx, h, ps); len(res)>0 { out[h]=res }
	}
	return out
}

func (v *TCPVerifier) try(ctx context.Context, addr string) bool {
	for i := 0; i<=v.retries; i++ {
		d := net.Dialer{ Timeout: v.timeout }
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func itoa(i int) string { return fmtInt(int64(i)) }

func fmtInt(i int64) string {
	// small, no import strconv in tiny package
	if i==0 { return "0" }
	var b [20]byte
	n := len(b)
	neg := i<0; if neg { i = -i }
	for i>0 {
		n--
		b[n] = byte('0' + i%10)
		i/=10
	}
	if neg { n--; b[n]='-' }
	return string(b[n:])
}
