package smuggling

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestSmugglingType_CL0_String(t *testing.T) {
	if TypeCL0.String() != "CL.0" {
		t.Errorf("expected CL.0, got %q", TypeCL0.String())
	}
	if Type0CL.String() != "0.CL" {
		t.Errorf("expected 0.CL, got %q", Type0CL.String())
	}
}

func TestBuildCL0Payload(t *testing.T) {
	p := BuildCL0Payload("example.com", "/", "assaycanary")
	if !strings.HasPrefix(p, "GET / HTTP/1.1\r\n") {
		t.Errorf("expected outer GET request, got:\n%s", p)
	}
	if !strings.Contains(p, "Content-Length: ") {
		t.Error("expected a Content-Length header")
	}
	if !strings.Contains(p, "Connection: keep-alive") {
		t.Error("expected keep-alive so the smuggled request is processed on the same connection")
	}
	if !strings.Contains(p, "GET /assaycanary HTTP/1.1") {
		t.Error("expected the smuggled request in the body")
	}
	// The Content-Length must exactly cover the smuggled body, or a compliant
	// server would not desync.
	idx := strings.Index(p, "\r\n\r\n")
	body := p[idx+4:]
	if !strings.Contains(p, "Content-Length: "+itoa(len(body))) {
		t.Errorf("Content-Length must equal body length %d; payload:\n%s", len(body), p)
	}
}

func TestCountResponses(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 1},
		{"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 2},
		{"garbage", 0},
		{"", 0},
	}
	for _, c := range cases {
		if got := CountResponses(c.raw); got != c.want {
			t.Errorf("CountResponses(%q) = %d, want %d", c.raw, got, c.want)
		}
	}
}

// rawListener starts a TCP server whose handler controls the exact bytes
// written back, letting tests simulate CL.0-vulnerable vs safe back-ends.
func rawListener(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handler(conn)
		}
	}()
	return ln.Addr().String()
}

func TestDetector_DetectCL0_Vulnerable(t *testing.T) {
	addr := rawListener(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 8192)
		n, rerr := conn.Read(buf)
		if rerr != nil && n == 0 {
			return
		}
		req := string(buf[:n])
		// A CL.0-vulnerable back-end ignores the body's Content-Length and
		// processes the smuggled request, emitting a second response.
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
		if strings.Contains(req, "assaycanary") {
			resp += "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
		}
		if _, werr := conn.Write([]byte(resp)); werr != nil {
			return
		}
	})

	d := NewDetector()
	res := d.DetectCL0(context.Background(), "http://"+addr, "/")
	if !res.Vulnerable {
		t.Fatalf("expected CL.0 vulnerable, got: %+v", res)
	}
	if res.Type != TypeCL0 {
		t.Errorf("expected TypeCL0, got %v", res.Type)
	}
}

func TestDetector_DetectCL0_Safe(t *testing.T) {
	addr := rawListener(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 8192)
		if _, rerr := conn.Read(buf); rerr != nil {
			return
		}
		// A compliant back-end consumes the body and returns exactly one response.
		if _, werr := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")); werr != nil {
			return
		}
	})

	d := NewDetector()
	res := d.DetectCL0(context.Background(), "http://"+addr, "/")
	if res.Vulnerable {
		t.Fatalf("expected not vulnerable for compliant server, got: %+v", res)
	}
}

func TestDetector_DetectCL0_BadTarget(t *testing.T) {
	d := NewDetector()
	res := d.DetectCL0(context.Background(), "://bad", "/")
	if res.Vulnerable {
		t.Error("malformed target must not be reported vulnerable")
	}
}

// itoa is a tiny helper to avoid importing strconv in a couple of places.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
