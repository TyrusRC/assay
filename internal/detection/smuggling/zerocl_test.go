package smuggling

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestBuild0CLPayload(t *testing.T) {
	p := Build0CLPayload("example.com", "/", "assaycanary")
	if !strings.Contains(p, "Expect: 100-continue") {
		t.Error("0.CL payload must carry Expect: 100-continue (the 0.CL coaxing vector)")
	}
	if !strings.Contains(p, "Content-Length: ") {
		t.Error("expected a Content-Length header")
	}
	if !strings.Contains(p, "GET /assaycanary HTTP/1.1") {
		t.Error("expected the smuggled request in the body")
	}
	idx := strings.Index(p, "\r\n\r\n")
	body := p[idx+4:]
	if !strings.Contains(p, "Content-Length: "+itoa(len(body))) {
		t.Errorf("Content-Length must equal body length %d:\n%s", len(body), p)
	}
}

func TestDetector_Detect0CL_Vulnerable(t *testing.T) {
	addr := rawListener(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 8192)
		n, rerr := conn.Read(buf)
		if rerr != nil && n == 0 {
			return
		}
		req := string(buf[:n])
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
		// A 0.CL-vulnerable back-end reads the body the front-end thought
		// absent, processing the smuggled request → second response.
		if strings.Contains(req, "assaycanary") {
			resp += "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
		}
		if _, werr := conn.Write([]byte(resp)); werr != nil {
			return
		}
	})

	d := NewDetector()
	res := d.Detect0CL(context.Background(), "http://"+addr, "/")
	if !res.Vulnerable {
		t.Fatalf("expected 0.CL vulnerable, got: %+v", res)
	}
	if res.Type != Type0CL {
		t.Errorf("expected Type0CL, got %v", res.Type)
	}
}

func TestDetector_Detect0CL_Safe(t *testing.T) {
	addr := rawListener(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 8192)
		if _, rerr := conn.Read(buf); rerr != nil {
			return
		}
		if _, werr := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")); werr != nil {
			return
		}
	})

	d := NewDetector()
	res := d.Detect0CL(context.Background(), "http://"+addr, "/")
	if res.Vulnerable {
		t.Fatalf("compliant server must not be flagged: %+v", res)
	}
}

func TestDetector_Detect0CL_BadTarget(t *testing.T) {
	d := NewDetector()
	if res := d.Detect0CL(context.Background(), "://bad", "/"); res.Vulnerable {
		t.Error("malformed target must not be reported vulnerable")
	}
}
