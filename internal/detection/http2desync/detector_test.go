package http2desync

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

func TestDetector_NameAndDescription(t *testing.T) {
	d := New()
	if d.Name() != "http2desync" {
		t.Errorf("Name() = %q, want http2desync", d.Name())
	}
	if d.Description() == "" {
		t.Error("Description() is empty")
	}
}

// startBackend launches a TCP listener whose accept loop hands every
// connection to handler. Returns the host:port string and a cleanup
// func. Used to simulate misbehaving frontends/backends precisely —
// httptest.NewServer can't, because net/http normalizes everything.
func startBackend(t *testing.T, handler func(net.Conn)) (addr string, cleanup func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(done)
				return
			}
			go handler(c)
		}
	}()
	return l.Addr().String(), func() {
		_ = l.Close()
		<-done
	}
}

// TestProbeH2cUpgrade_Accepted covers a frontend that returns
// 101 Switching Protocols when sent an Upgrade: h2c header — the
// signal that h2c smuggling chains may be possible. Real-world impact
// depends on the downstream proxy, but the 101 alone warrants a
// finding because cleartext HTTP/2 prior-knowledge is rarely safe.
func TestProbeH2cUpgrade_Accepted(t *testing.T) {
	addr, cleanup := startBackend(t, func(c net.Conn) {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n"))
	})
	defer cleanup()

	d := New()
	res, err := d.Detect(context.Background(), "http://"+addr, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !containsTechnique(res.Techniques, "h2c_upgrade") {
		t.Errorf("expected technique h2c_upgrade; got %v", res.Techniques)
	}
	hasFinding := false
	for _, f := range res.Findings {
		if strings.Contains(strings.ToLower(f.Title), "h2c") {
			hasFinding = true
			if f.Severity != core.SeverityMedium && f.Severity != core.SeverityHigh {
				t.Errorf("h2c finding severity should be medium/high, got %q", f.Severity)
			}
		}
	}
	if !hasFinding {
		t.Error("expected at least one h2c finding")
	}
}

// TestProbeH2cUpgrade_Refused ensures a server that returns a normal
// 200 response (no 101) does not trigger a finding.
func TestProbeH2cUpgrade_Refused(t *testing.T) {
	addr, cleanup := startBackend(t, func(c net.Conn) {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	})
	defer cleanup()

	d := New()
	res, err := d.Detect(context.Background(), "http://"+addr, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if containsTechnique(res.Techniques, "h2c_upgrade") {
		t.Errorf("h2c_upgrade flagged on benign 200; techniques=%v", res.Techniques)
	}
}

// TestProbeCL0_TimingAnomaly covers the CL.0 desync probe: a backend
// that *should* return immediately on a request with Content-Length: 0
// but instead hangs (because it has been duped into reading the body
// as the start of a smuggled request). Detection is by timing diff
// against a clean baseline.
func TestProbeCL0_TimingAnomaly(t *testing.T) {
	addr, cleanup := startBackend(t, func(c net.Conn) {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 8192)
		n, _ := c.Read(buf)
		req := string(buf[:n])
		// Baseline POST with CL: 1 — respond immediately.
		// CL:0 with body smuggling — stall to mimic a desynced backend.
		if strings.Contains(req, "Content-Length: 0") && strings.Contains(req, "GET /smuggled") {
			// Pretend we are now waiting for more data (the smuggled
			// request). Sleep past the detector's CL.0 timing threshold.
			time.Sleep(800 * time.Millisecond)
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	})
	defer cleanup()

	d := New()
	res, err := d.Detect(context.Background(), "http://"+addr, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !containsTechnique(res.Techniques, "cl0_desync") {
		t.Errorf("expected technique cl0_desync; got %v", res.Techniques)
	}
	hasCritical := false
	for _, f := range res.Findings {
		if strings.Contains(strings.ToLower(f.Title), "cl.0") || strings.Contains(strings.ToLower(f.Title), "cl0") {
			if f.Severity == core.SeverityCritical || f.Severity == core.SeverityHigh {
				hasCritical = true
			}
		}
	}
	if !hasCritical {
		t.Error("expected CL.0 finding with high/critical severity")
	}
}

// TestProbeCL0_NoAnomaly_NoFinding ensures a backend that responds
// promptly to CL:0 + body (i.e., ignores the body, no desync) is not
// flagged.
func TestProbeCL0_NoAnomaly_NoFinding(t *testing.T) {
	addr, cleanup := startBackend(t, func(c net.Conn) {
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8192)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	})
	defer cleanup()

	d := New()
	res, err := d.Detect(context.Background(), "http://"+addr, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if containsTechnique(res.Techniques, "cl0_desync") {
		t.Errorf("cl0_desync flagged on benign backend; techniques=%v", res.Techniques)
	}
}

func containsTechnique(list []string, needle string) bool {
	for _, s := range list {
		if s == needle {
			return true
		}
	}
	return false
}
