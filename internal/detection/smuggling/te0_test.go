package smuggling

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestBuildTE0Payload(t *testing.T) {
	p := BuildTE0Payload("example.com", "/", "assaycanary")
	if !strings.Contains(p, "Transfer-Encoding: chunked") {
		t.Error("TE.0 payload must carry Transfer-Encoding: chunked")
	}
	if strings.Contains(p, "Content-Length: ") {
		t.Error("TE.0 payload must not carry a Content-Length header")
	}
	if !strings.Contains(p, "GET /assaycanary HTTP/1.1") {
		t.Error("expected the smuggled request in the chunked body")
	}
	if !strings.HasSuffix(p, "0\r\n\r\n") {
		t.Errorf("chunked body must end with the zero-chunk terminator:\n%s", p)
	}
}

func TestDetector_DetectTE0_Vulnerable(t *testing.T) {
	addr := rawListener(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 8192)
		n, rerr := conn.Read(buf)
		if rerr != nil && n == 0 {
			return
		}
		req := string(buf[:n])
		resp := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
		// A TE.0-vulnerable back-end ignores Transfer-Encoding and treats the
		// chunked body as a new request, processing the smuggled GET → second
		// response on the same connection.
		if strings.Contains(req, "assaycanary") {
			resp += "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
		}
		if _, werr := conn.Write([]byte(resp)); werr != nil {
			return
		}
	})

	d := NewDetector()
	res := d.DetectTE0(context.Background(), "http://"+addr, "/")
	if !res.Vulnerable {
		t.Fatalf("expected TE.0 vulnerable, got: %+v", res)
	}
	if res.Type != TypeTE0 {
		t.Errorf("expected TypeTE0, got %v", res.Type)
	}
}

func TestDetector_DetectTE0_Safe(t *testing.T) {
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
	res := d.DetectTE0(context.Background(), "http://"+addr, "/")
	if res.Vulnerable {
		t.Fatalf("compliant server must not be flagged: %+v", res)
	}
}

func TestDetector_DetectTE0_BadTarget(t *testing.T) {
	d := NewDetector()
	if res := d.DetectTE0(context.Background(), "://bad", "/"); res.Vulnerable {
		t.Error("malformed target must not be reported vulnerable")
	}
}
