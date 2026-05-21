package hosthdr

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	internalhttp "github.com/TyrusRC/assay/internal/http"
)

// TestAdvanced_ForwardedHostConfusion_Reflected verifies that a server which
// honors X-Forwarded-Host (or Forwarded: host=) by reflecting that value into
// a Location/redirect or body is flagged Critical. This is the canonical
// cache-poisoning-via-XFH pattern.
func TestAdvanced_ForwardedHostConfusion_Reflected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable: trust X-Forwarded-Host first, then Forwarded.
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			if fwd := r.Header.Get("Forwarded"); fwd != "" {
				// crude parser: host=value
				for _, p := range strings.Split(fwd, ";") {
					p = strings.TrimSpace(p)
					if strings.HasPrefix(strings.ToLower(p), "host=") {
						host = strings.TrimPrefix(p, "host=")
						host = strings.TrimPrefix(host, "Host=")
					}
				}
			}
		}
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Location", "https://"+host+"/next")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)
	res, err := d.DetectForwardedHostConfusion(context.Background(), server.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("DetectForwardedHostConfusion: %v", err)
	}
	if !res.Vulnerable || len(res.Findings) == 0 {
		t.Fatalf("expected forwarded-host finding, got %d findings", len(res.Findings))
	}
	hit := false
	for _, f := range res.Findings {
		if f.Type == "Host Header Cache Poisoning via X-Forwarded-Host" {
			hit = true
			if f.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", f.Severity)
			}
			if f.Tool != "hosthdr-advanced-detector" {
				t.Errorf("expected tool=hosthdr-advanced-detector, got %s", f.Tool)
			}
		}
	}
	if !hit {
		t.Fatalf("missing expected finding type, got: %+v", res.Findings)
	}
}

// TestAdvanced_ForwardedHostConfusion_Hardened verifies a server that
// always emits its canonical host produces no finding.
func TestAdvanced_ForwardedHostConfusion_Hardened(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hardened: always emit canonical Location.
		w.Header().Set("Location", "https://canonical.example.com/next")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	client := internalhttp.NewClient().WithFollowRedirects(false)
	d := New(client)
	res, err := d.DetectForwardedHostConfusion(context.Background(), server.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("DetectForwardedHostConfusion: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("expected no findings on hardened server, got %d: %+v", len(res.Findings), res.Findings)
	}
}

// TestAdvanced_ForwardedHostConfusion_BaselineEcho_NotFlagged guards
// against FP when the attacker host happens to already appear in the
// baseline body (which means the host wasn't actually injected).
func TestAdvanced_ForwardedHostConfusion_BaselineEcho_NotFlagged(t *testing.T) {
	opts := DefaultOptions()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Both baseline and probe contain the attacker string; this means
		// the server didn't actually honor the injection.
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>Welcome to %s</body></html>", opts.AttackerHost)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	res, err := d.DetectForwardedHostConfusion(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatalf("DetectForwardedHostConfusion: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("baseline-echo must not trigger forwarded-host finding, got %d", len(res.Findings))
	}
}

// TestAdvanced_AbsoluteURIVsHostConflict_Vulnerable wires up a raw TCP
// server that records both the request-line authority and the Host header
// and reports which one drove routing. We send an absolute-URI request:
//
//	GET http://target/path HTTP/1.1
//	Host: attacker.example
//
// RFC 7230 says the absolute-URI authority MUST win — if our test server
// instead routes by Host, we flag.
func TestAdvanced_AbsoluteURIVsHostConflict_Vulnerable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				req := string(buf[:n])
				// Vulnerable: respond with whichever Host header was sent
				// (ignoring the absolute-URI authority on the request line).
				host := "unknown"
				for _, line := range strings.Split(req, "\r\n") {
					if strings.HasPrefix(strings.ToLower(line), "host:") {
						host = strings.TrimSpace(line[len("host:"):])
						break
					}
				}
				body := "routed-by-host:" + host
				resp := "HTTP/1.1 200 OK\r\n" +
					"Content-Type: text/plain\r\n" +
					fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
					"Connection: close\r\n\r\n" + body
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	target := "http://" + ln.Addr().String() + "/path"
	client := internalhttp.NewClient()
	d := New(client)
	opts := DefaultOptions()
	res, err := d.DetectAbsoluteURIVsHostConflict(context.Background(), target, opts)
	if err != nil {
		t.Fatalf("DetectAbsoluteURIVsHostConflict: %v", err)
	}
	if !res.Vulnerable || len(res.Findings) == 0 {
		t.Fatalf("expected absolute-URI-vs-Host finding, got %d", len(res.Findings))
	}
	hit := false
	for _, f := range res.Findings {
		if f.Type == "Absolute-URI vs Host Header Conflict" {
			hit = true
			if f.Severity != "high" {
				t.Errorf("expected high severity, got %s", f.Severity)
			}
		}
	}
	if !hit {
		t.Fatalf("missing expected finding type: %+v", res.Findings)
	}
}

// TestAdvanced_AbsoluteURIVsHostConflict_Hardened verifies a server that
// routes on the absolute-URI authority (echoing it back, ignoring Host)
// does NOT trip the detector.
func TestAdvanced_AbsoluteURIVsHostConflict_Hardened(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				req := string(buf[:n])
				// Hardened: echo back the absolute URI from the request
				// line (the canonical authority). Host header is ignored.
				authority := "canonical"
				lines := strings.Split(req, "\r\n")
				if len(lines) > 0 {
					parts := strings.Fields(lines[0])
					if len(parts) >= 2 {
						if u, err := url.Parse(parts[1]); err == nil && u.Host != "" {
							authority = u.Host
						}
					}
				}
				body := "routed-by-authority:" + authority
				resp := "HTTP/1.1 200 OK\r\n" +
					"Content-Type: text/plain\r\n" +
					fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
					"Connection: close\r\n\r\n" + body
				_, _ = c.Write([]byte(resp))
			}(conn)
		}
	}()

	target := "http://" + ln.Addr().String() + "/path"
	client := internalhttp.NewClient()
	d := New(client)
	res, err := d.DetectAbsoluteURIVsHostConflict(context.Background(), target, DefaultOptions())
	if err != nil {
		t.Fatalf("DetectAbsoluteURIVsHostConflict: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("hardened server flagged: %+v", res.Findings)
	}
}

// TestAdvanced_CachePoisoningViaHost_Vulnerable simulates a naive cache
// in front of an origin: the cache key is just the path+query, the body
// stored is whatever the origin produced (which includes the poisoned
// X-Forwarded-Host the attacker sent). A second client requests the same
// path WITHOUT the attacker header and gets the poisoned body — flag.
func TestAdvanced_CachePoisoningViaHost_Vulnerable(t *testing.T) {
	var (
		mu    sync.Mutex
		cache = make(map[string]string)
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path + "?" + r.URL.RawQuery
		mu.Lock()
		cached, ok := cache[key]
		mu.Unlock()
		if ok {
			w.Header().Set("X-Cache", "HIT")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, cached)
			return
		}
		// MISS: origin reflects X-Forwarded-Host into a canonical link
		// (the classic vulnerable build).
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		body := fmt.Sprintf(`<html><head><link rel="canonical" href="https://%s/"></head></html>`, host)
		mu.Lock()
		cache[key] = body
		mu.Unlock()
		w.Header().Set("X-Cache", "MISS")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, body)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DefaultOptions()
	opts.CacheTestEnabled = true

	res, err := d.DetectCachePoisoningViaHost(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatalf("DetectCachePoisoningViaHost: %v", err)
	}
	if !res.Vulnerable || len(res.Findings) == 0 {
		t.Fatalf("expected cache-poisoning finding, got %d", len(res.Findings))
	}
	hit := false
	for _, f := range res.Findings {
		if f.Type == "Cache Poisoning via Host Header" {
			hit = true
			if f.Severity != "critical" {
				t.Errorf("expected critical severity, got %s", f.Severity)
			}
		}
	}
	if !hit {
		t.Fatalf("missing cache-poisoning finding: %+v", res.Findings)
	}
}

// TestAdvanced_CachePoisoningViaHost_Disabled verifies the detector
// returns no findings (and no error) when CacheTestEnabled is false.
func TestAdvanced_CachePoisoningViaHost_Disabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		fmt.Fprintf(w, `<link rel="canonical" href="https://%s/">`, host)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DefaultOptions()
	opts.CacheTestEnabled = false

	res, err := d.DetectCachePoisoningViaHost(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatalf("DetectCachePoisoningViaHost: %v", err)
	}
	if res.Vulnerable || len(res.Findings) != 0 {
		t.Fatalf("expected zero findings when cache test disabled, got %d", len(res.Findings))
	}
}

// TestAdvanced_CachePoisoningViaHost_NoCache verifies a fresh origin
// (no cache, each request gets its own body) does NOT trigger a finding.
func TestAdvanced_CachePoisoningViaHost_NoCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No caching: always echo the *current* request's host.
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<link rel="canonical" href="https://%s/">`, host)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DefaultOptions()
	opts.CacheTestEnabled = true

	res, err := d.DetectCachePoisoningViaHost(context.Background(), server.URL, opts)
	if err != nil {
		t.Fatalf("DetectCachePoisoningViaHost: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("no-cache origin must not trigger finding, got: %+v", res.Findings)
	}
}
