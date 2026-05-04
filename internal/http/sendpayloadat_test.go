package http

import (
	"context"
	"io"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
)

// captureServer records the most recent request shape for assertion.
type captureServer struct {
	mu       sync.Mutex
	method   string
	path     string
	rawQuery string
	body     string
	cookies  []*nethttp.Cookie
	headers  nethttp.Header
}

func newCaptureServer(t *testing.T) (*httptest.Server, *captureServer) {
	t.Helper()
	cap := &captureServer{}
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		cap.mu.Lock()
		defer cap.mu.Unlock()
		cap.method = r.Method
		cap.path = r.URL.Path
		cap.rawQuery = r.URL.RawQuery
		cap.cookies = r.Cookies()
		cap.headers = r.Header.Clone()
		body, _ := io.ReadAll(r.Body)
		cap.body = string(body)
		w.WriteHeader(nethttp.StatusOK)
	}))
	return srv, cap
}

// TestSendPayloadAt_QueryUsesQueryString verifies the default branch
// for query-located params still injects into the query string for
// GET requests (the legacy SendPayload behavior).
func TestSendPayloadAt_QueryUsesQueryString(t *testing.T) {
	srv, cap := newCaptureServer(t)
	defer srv.Close()

	c := NewClient().WithTimeout(5 * time.Second)
	param := core.Parameter{Name: "id", Location: core.ParamLocationQuery}
	_, err := c.SendPayloadAt(context.Background(), srv.URL+"/x", param, "INJECTED", "GET")
	if err != nil {
		t.Fatalf("SendPayloadAt: %v", err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if !strings.Contains(cap.rawQuery, "id=INJECTED") {
		t.Errorf("query injection failed: rawQuery=%q", cap.rawQuery)
	}
	if cap.method != "GET" {
		t.Errorf("method = %q, want GET", cap.method)
	}
	if cap.body != "" {
		t.Errorf("body should be empty for GET query injection, got %q", cap.body)
	}
}

// TestSendPayloadAt_PathReplacesSegment verifies path-located params
// land in the URL path at the recorded SegmentIndex, not in query.
func TestSendPayloadAt_PathReplacesSegment(t *testing.T) {
	srv, cap := newCaptureServer(t)
	defer srv.Close()

	c := NewClient().WithTimeout(5 * time.Second)
	param := core.Parameter{
		Name:         "path_1",
		Location:     core.ParamLocationPath,
		SegmentIndex: 1,
	}
	// Path /api/users/42 — segment 0 is "api", 1 is "users", 2 is "42".
	_, err := c.SendPayloadAt(context.Background(), srv.URL+"/api/users/42", param, "PWNED", "GET")
	if err != nil {
		t.Fatalf("SendPayloadAt: %v", err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if cap.path != "/api/PWNED/42" {
		t.Errorf("path = %q, want /api/PWNED/42", cap.path)
	}
	if strings.Contains(cap.rawQuery, "PWNED") {
		t.Errorf("path payload leaked into query: %q", cap.rawQuery)
	}
}

// TestSendPayloadAt_HeaderInjectsHeaderValue verifies header-located
// params end up in the request header map.
func TestSendPayloadAt_HeaderInjectsHeaderValue(t *testing.T) {
	srv, cap := newCaptureServer(t)
	defer srv.Close()

	c := NewClient().WithTimeout(5 * time.Second)
	param := core.Parameter{Name: "X-Custom-Test", Location: core.ParamLocationHeader}
	_, err := c.SendPayloadAt(context.Background(), srv.URL+"/x", param, "HDR-PWNED", "GET")
	if err != nil {
		t.Fatalf("SendPayloadAt: %v", err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if got := cap.headers.Get("X-Custom-Test"); got != "HDR-PWNED" {
		t.Errorf("header value = %q, want HDR-PWNED", got)
	}
	if strings.Contains(cap.rawQuery, "HDR-PWNED") {
		t.Errorf("header payload leaked into query: %q", cap.rawQuery)
	}
}

// TestSendPayloadAt_CookieInjectsCookieJar verifies cookie-located
// params are sent as a Cookie header value.
func TestSendPayloadAt_CookieInjectsCookieJar(t *testing.T) {
	srv, cap := newCaptureServer(t)
	defer srv.Close()

	c := NewClient().WithTimeout(5 * time.Second)
	param := core.Parameter{Name: "session", Location: core.ParamLocationCookie}
	_, err := c.SendPayloadAt(context.Background(), srv.URL+"/x", param, "CK-PWNED", "GET")
	if err != nil {
		t.Fatalf("SendPayloadAt: %v", err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	found := false
	for _, c := range cap.cookies {
		if c.Name == "session" && c.Value == "CK-PWNED" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("cookie injection failed; cookies=%v", cap.cookies)
	}
}

// TestSendPayloadAt_BodyJSONUsedWhenContentTypeJSON verifies the JSON
// dispatch fires when ContentType says JSON, regardless of method.
func TestSendPayloadAt_BodyJSONUsedWhenContentTypeJSON(t *testing.T) {
	srv, cap := newCaptureServer(t)
	defer srv.Close()

	c := NewClient().WithTimeout(5 * time.Second)
	param := core.Parameter{
		Name:        "username",
		Location:    core.ParamLocationBody,
		ContentType: "application/json",
	}
	_, err := c.SendPayloadAt(context.Background(), srv.URL+"/api", param, "JSON-PWNED", "POST")
	if err != nil {
		t.Fatalf("SendPayloadAt: %v", err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if !strings.Contains(cap.body, `"username"`) || !strings.Contains(cap.body, "JSON-PWNED") {
		t.Errorf("expected JSON body containing username and JSON-PWNED; got %q", cap.body)
	}
	if got := cap.headers.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
}

// TestSendPayloadAt_BodyJSONInferredFromDottedName verifies the JSON
// dispatch also fires when ContentType is unset but the param name
// looks like a JSON path (contains a dot).
func TestSendPayloadAt_BodyJSONInferredFromDottedName(t *testing.T) {
	srv, cap := newCaptureServer(t)
	defer srv.Close()

	c := NewClient().WithTimeout(5 * time.Second)
	param := core.Parameter{
		Name:     "user.email",
		Location: core.ParamLocationBody,
	}
	_, err := c.SendPayloadAt(context.Background(), srv.URL+"/api", param, "DOT-JSON-PWNED", "POST")
	if err != nil {
		t.Fatalf("SendPayloadAt: %v", err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if got := cap.headers.Get("Content-Type"); got != "application/json" {
		t.Errorf("dotted name should infer JSON; Content-Type = %q", got)
	}
}

// TestSendPayloadAt_BodyXMLUsedWhenContentTypeXML verifies XML dispatch.
func TestSendPayloadAt_BodyXMLUsedWhenContentTypeXML(t *testing.T) {
	srv, cap := newCaptureServer(t)
	defer srv.Close()

	c := NewClient().WithTimeout(5 * time.Second)
	param := core.Parameter{
		Name:        "envelope",
		Location:    core.ParamLocationBody,
		ContentType: "text/xml",
	}
	_, err := c.SendPayloadAt(context.Background(), srv.URL+"/api", param, "XML-PWNED", "POST")
	if err != nil {
		t.Fatalf("SendPayloadAt: %v", err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if !strings.Contains(cap.body, "<envelope>XML-PWNED</envelope>") {
		t.Errorf("expected XML element; got %q", cap.body)
	}
	if got := cap.headers.Get("Content-Type"); got != "text/xml" {
		t.Errorf("Content-Type = %q, want text/xml", got)
	}
}

// TestSendPayloadAt_BodyDefaultsToFormURLEncoded preserves the legacy
// behavior for body params without a specific ContentType.
func TestSendPayloadAt_BodyDefaultsToFormURLEncoded(t *testing.T) {
	srv, cap := newCaptureServer(t)
	defer srv.Close()

	c := NewClient().WithTimeout(5 * time.Second)
	param := core.Parameter{Name: "username", Location: core.ParamLocationBody}
	_, err := c.SendPayloadAt(context.Background(), srv.URL+"/api", param, "FORM-PWNED", "POST")
	if err != nil {
		t.Fatalf("SendPayloadAt: %v", err)
	}
	cap.mu.Lock()
	defer cap.mu.Unlock()
	if got := cap.headers.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want form-urlencoded", got)
	}
	if !strings.Contains(cap.body, "username=FORM-PWNED") {
		t.Errorf("expected form-urlencoded body; got %q", cap.body)
	}
}

// TestSendPayloadAt_StorageDoesNotInject confirms localstorage and
// sessionstorage params produce a baseline GET with no payload anywhere
// — they're not addressable from outside the browser.
func TestSendPayloadAt_StorageDoesNotInject(t *testing.T) {
	srv, cap := newCaptureServer(t)
	defer srv.Close()

	c := NewClient().WithTimeout(5 * time.Second)
	for _, loc := range []string{core.ParamLocationLocalStorage, core.ParamLocationSessionStorage} {
		t.Run(loc, func(t *testing.T) {
			param := core.Parameter{Name: "auth_token", Location: loc}
			_, err := c.SendPayloadAt(context.Background(), srv.URL+"/x", param, "STORAGE-PWNED", "GET")
			if err != nil {
				t.Fatalf("SendPayloadAt: %v", err)
			}
			cap.mu.Lock()
			defer cap.mu.Unlock()
			if cap.method != "GET" {
				t.Errorf("storage probe should be GET, got %q", cap.method)
			}
			if strings.Contains(cap.rawQuery, "STORAGE-PWNED") || strings.Contains(cap.body, "STORAGE-PWNED") {
				t.Errorf("storage payload leaked into wire: q=%q b=%q", cap.rawQuery, cap.body)
			}
		})
	}
}
