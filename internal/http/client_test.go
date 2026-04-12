package http

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("NewClient() returned nil")
	}
}

func TestClient_Get(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Test</body></html>"))
	}))
	defer server.Close()

	client := NewClient()
	resp, err := client.Get(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if resp.Body == "" {
		t.Error("Body should not be empty")
	}
}

func TestClient_Post(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("Content-Type header not set correctly")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	client := NewClient()
	resp, err := client.Post(context.Background(), server.URL, "username=test&password=test")

	if err != nil {
		t.Fatalf("Post() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestClient_WithHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token123" {
			t.Error("Authorization header not set")
		}
		if r.Header.Get("X-Custom") != "value" {
			t.Error("X-Custom header not set")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient().WithHeaders(map[string]string{
		"Authorization": "Bearer token123",
		"X-Custom":      "value",
	})

	_, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestClient_WithCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie := r.Header.Get("Cookie")
		if cookie != "session=abc123" {
			t.Errorf("Cookie = %q, want %q", cookie, "session=abc123")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient().WithCookies("session=abc123")
	_, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestClient_WithProxy(t *testing.T) {
	client := NewClient().WithProxy("http://127.0.0.1:8080")
	if client.proxyURL != "http://127.0.0.1:8080" {
		t.Error("Proxy URL not set")
	}
}

func TestClient_WithTimeout(t *testing.T) {
	client := NewClient().WithTimeout(5 * time.Second)
	if client.timeout != 5*time.Second {
		t.Error("Timeout not set")
	}
}

func TestClient_Do(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("Expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient()
	req := &Request{
		Method: http.MethodPut,
		URL:    server.URL,
		Body:   `{"data": "test"}`,
	}

	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestResponse_Headers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "test-value")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	client := NewClient()
	resp, err := client.Get(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if resp.Headers["X-Custom-Header"] != "test-value" {
		t.Error("Custom header not captured")
	}
	if resp.ContentType != "application/json" {
		t.Errorf("ContentType = %q, want %q", resp.ContentType, "application/json")
	}
}

func TestClient_FollowRedirects(t *testing.T) {
	redirectCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redirectCount == 0 {
			redirectCount++
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Final destination"))
	}))
	defer server.Close()

	client := NewClient().WithFollowRedirects(true)
	resp, err := client.Get(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if resp.Body != "Final destination" {
		t.Error("Did not follow redirect")
	}
}

func TestClient_NoFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	}))
	defer server.Close()

	client := NewClient().WithFollowRedirects(false)
	resp, err := client.Get(context.Background(), server.URL)

	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Errorf("StatusCode = %d, want %d (should not follow redirect)", resp.StatusCode, http.StatusFound)
	}
}

func TestClient_PostJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want %q", r.Header.Get("Content-Type"), "application/json")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer server.Close()

	client := NewClient()
	resp, err := client.PostJSON(context.Background(), server.URL, `{"name": "test"}`)

	if err != nil {
		t.Fatalf("PostJSON() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestClient_SendPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("param=" + param))
	}))
	defer server.Close()

	client := NewClient()
	resp, err := client.SendPayload(context.Background(), server.URL+"?id=original", "id", "injected", "GET")

	if err != nil {
		t.Fatalf("SendPayload() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if resp.Body != "param=injected" {
		t.Errorf("Body = %q, want %q", resp.Body, "param=injected")
	}
	if resp.OriginalValue != "original" {
		t.Errorf("OriginalValue = %q, want %q", resp.OriginalValue, "original")
	}
}

func TestClient_SendPayload_NoExistingParam(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := NewClient()
	resp, err := client.SendPayload(context.Background(), server.URL, "newparam", "value", "GET")

	if err != nil {
		t.Fatalf("SendPayload() error = %v", err)
	}
	if resp.OriginalValue != "" {
		t.Errorf("OriginalValue = %q, want empty", resp.OriginalValue)
	}
}

func TestClient_SendPayload_InvalidURL(t *testing.T) {
	client := NewClient()
	_, err := client.SendPayload(context.Background(), "://invalid", "id", "test", "GET")

	if err == nil {
		t.Error("SendPayload() should return error for invalid URL")
	}
}

func TestClient_SendRawBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "text/xml" {
			t.Errorf("Content-Type = %q, want %q", r.Header.Get("Content-Type"), "text/xml")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient()
	resp, err := client.SendRawBody(context.Background(), server.URL, http.MethodPost, "<xml>data</xml>", "text/xml")

	if err != nil {
		t.Fatalf("SendRawBody() error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestClient_Clone(t *testing.T) {
	original := NewClient().
		WithHeaders(map[string]string{"X-Custom": "value"}).
		WithCookies("session=abc").
		WithUserAgent("CustomAgent/1.0").
		WithTimeout(10 * time.Second)

	cloned := original.Clone()

	// Verify cloned fields match
	if cloned.cookies != original.cookies {
		t.Errorf("Cloned cookies = %q, want %q", cloned.cookies, original.cookies)
	}
	if cloned.timeout != original.timeout {
		t.Errorf("Cloned timeout = %v, want %v", cloned.timeout, original.timeout)
	}
	if cloned.userAgent != original.userAgent {
		t.Errorf("Cloned userAgent = %q, want %q", cloned.userAgent, original.userAgent)
	}
	if cloned.headers["X-Custom"] != "value" {
		t.Error("Cloned headers should contain X-Custom")
	}

	// Verify independence: modifying clone does not affect original
	cloned.headers["X-New"] = "new"
	if _, exists := original.headers["X-New"]; exists {
		t.Error("Modifying cloned headers should not affect original")
	}
}

func TestClient_Clone_WithInsecure(t *testing.T) {
	original := NewClient().WithInsecure(true)
	cloned := original.Clone()

	if !cloned.insecure {
		t.Error("Cloned insecure should be true")
	}
}

func TestClient_Clone_WithProxy(t *testing.T) {
	original := NewClient().WithProxy("http://proxy:8080")
	cloned := original.Clone()

	if cloned.proxyURL != "http://proxy:8080" {
		t.Errorf("Cloned proxyURL = %q", cloned.proxyURL)
	}
}

func TestClient_Clone_WithFollowRedirects(t *testing.T) {
	original := NewClient().WithFollowRedirects(false)
	cloned := original.Clone()

	if cloned.followRedirects {
		t.Error("Cloned followRedirects should be false")
	}
}

func TestClient_WithInsecure(t *testing.T) {
	client := NewClient().WithInsecure(true)

	if !client.insecure {
		t.Error("Insecure should be true")
	}
}

func TestClient_WithUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua != "CustomAgent/2.0" {
			t.Errorf("User-Agent = %q, want %q", ua, "CustomAgent/2.0")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient().WithUserAgent("CustomAgent/2.0")
	_, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestClient_EnsureClient_ThreadSafety(t *testing.T) {
	client := NewClient().WithProxy("http://proxy:8080")
	// httpClient is nil after WithProxy due to rebuildNeeded

	done := make(chan bool, 10)
	for range 10 {
		go func() {
			client.ensureClient()
			done <- true
		}()
	}

	for range 10 {
		<-done
	}

	// No panic or race condition = pass
	if client.httpClient == nil {
		t.Error("httpClient should not be nil after ensureClient")
	}
}

func TestClient_RebuildNeeded_NilsClient(t *testing.T) {
	client := NewClient()
	if client.httpClient == nil {
		t.Error("httpClient should not be nil after NewClient")
	}

	client.rebuildNeeded()
	if client.httpClient != nil {
		t.Error("httpClient should be nil after rebuildNeeded")
	}
}

func TestClient_Do_InvalidURL(t *testing.T) {
	client := NewClient()
	_, err := client.Do(context.Background(), &Request{
		Method: http.MethodGet,
		URL:    "://invalid",
	})

	if err == nil {
		t.Error("Do() should return error for invalid URL")
	}
}

func TestClient_Do_RequestSpecificHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Request-Header") != "request-value" {
			t.Errorf("X-Request-Header = %q", r.Header.Get("X-Request-Header"))
		}
		if r.Header.Get("X-Client-Header") != "client-value" {
			t.Errorf("X-Client-Header = %q", r.Header.Get("X-Client-Header"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient().WithHeaders(map[string]string{"X-Client-Header": "client-value"})

	_, err := client.Do(context.Background(), &Request{
		Method:  http.MethodGet,
		URL:     server.URL,
		Headers: map[string]string{"X-Request-Header": "request-value"},
	})
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
}

func TestClient_Do_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.Do(ctx, &Request{
		Method: http.MethodGet,
		URL:    server.URL,
	})

	if err == nil {
		t.Error("Do() should return error for cancelled context")
	}
}

func TestClient_Do_EmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client := NewClient()
	resp, err := client.Do(context.Background(), &Request{
		Method: http.MethodGet,
		URL:    server.URL,
	})

	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if resp.Body != "" {
		t.Errorf("Body = %q, want empty", resp.Body)
	}
}

func TestClient_Do_ResponseURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient()
	resp, err := client.Do(context.Background(), &Request{
		Method: http.MethodGet,
		URL:    server.URL + "/test/path",
	})

	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if resp.URL == "" {
		t.Error("Response URL should not be empty")
	}
}

func TestClient_Do_Duration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient()
	resp, err := client.Do(context.Background(), &Request{
		Method: http.MethodGet,
		URL:    server.URL,
	})

	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if resp.Duration <= 0 {
		t.Error("Response Duration should be positive")
	}
}

func TestClient_WithProxy_InvalidProxy(t *testing.T) {
	// Setting a proxy with a valid format but unreachable address
	client := NewClient().WithProxy("http://127.0.0.1:1")
	// httpClient is nil after WithProxy; ensureClient will rebuild
	client.ensureClient()

	if client.httpClient == nil {
		t.Error("httpClient should be built even with unreachable proxy")
	}
}

func TestClient_DefaultConstants(t *testing.T) {
	if DefaultTimeout != 30*time.Second {
		t.Errorf("DefaultTimeout = %v, want 30s", DefaultTimeout)
	}
	if MaxResponseBodySize != 10*1024*1024 {
		t.Errorf("MaxResponseBodySize = %d, want %d", MaxResponseBodySize, 10*1024*1024)
	}
}

func TestClient_DefaultUserAgent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua != "SKWS/1.0" {
			t.Errorf("Default User-Agent = %q, want %q", ua, "SKWS/1.0")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient()
	_, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
}

func TestRequest_Fields(t *testing.T) {
	req := &Request{
		Method:      "POST",
		URL:         "https://example.com",
		Headers:     map[string]string{"X-Custom": "value"},
		Body:        "data",
		ContentType: "application/json",
	}

	if req.Method != "POST" {
		t.Errorf("Method = %q", req.Method)
	}
	if req.URL != "https://example.com" {
		t.Errorf("URL = %q", req.URL)
	}
	if req.Body != "data" {
		t.Errorf("Body = %q", req.Body)
	}
}

func TestResponse_Fields(t *testing.T) {
	resp := &Response{
		StatusCode:    200,
		Status:        "200 OK",
		Headers:       map[string]string{"Content-Type": "text/html"},
		Body:          "<html></html>",
		ContentType:   "text/html",
		ContentLength: 13,
		URL:           "https://example.com",
		OriginalValue: "original",
	}

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d", resp.StatusCode)
	}
	if resp.OriginalValue != "original" {
		t.Errorf("OriginalValue = %q", resp.OriginalValue)
	}
}

func TestClient_BuildHTTPClient_WithProxy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied"))
	}))
	defer server.Close()

	// Create client with the test server as proxy
	client := NewClient().WithProxy(server.URL)
	client.ensureClient()

	if client.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
}

func TestClient_ChainedBuilderMethods(t *testing.T) {
	client := NewClient().
		WithHeaders(map[string]string{"A": "1"}).
		WithCookies("session=abc").
		WithProxy("http://proxy:8080").
		WithTimeout(5 * time.Second).
		WithFollowRedirects(false).
		WithUserAgent("Test/1.0").
		WithInsecure(true)

	if client.headers["A"] != "1" {
		t.Error("Headers not set")
	}
	if client.cookies != "session=abc" {
		t.Error("Cookies not set")
	}
	if client.proxyURL != "http://proxy:8080" {
		t.Error("Proxy not set")
	}
	if client.timeout != 5*time.Second {
		t.Error("Timeout not set")
	}
	if client.followRedirects {
		t.Error("FollowRedirects not set")
	}
	if client.userAgent != "Test/1.0" {
		t.Error("UserAgent not set")
	}
	if !client.insecure {
		t.Error("Insecure not set")
	}
}

// --- Phase 3: Multi-Vector Injection Tests ---

func TestClient_SendPayloadInHeader(t *testing.T) {
	tests := []struct {
		name       string
		headerName string
		payload    string
		method     string
	}{
		{
			name:       "inject into X-Forwarded-For header",
			headerName: "X-Forwarded-For",
			payload:    "127.0.0.1",
			method:     "GET",
		},
		{
			name:       "inject into Referer header",
			headerName: "Referer",
			payload:    "http://evil.com",
			method:     "POST",
		},
		{
			name:       "inject into custom header",
			headerName: "X-Custom-Test",
			payload:    "<script>alert(1)</script>",
			method:     "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got := r.Header.Get(tt.headerName)
				if got != tt.payload {
					t.Errorf("Header %q = %q, want %q", tt.headerName, got, tt.payload)
				}
				if r.Method != tt.method {
					t.Errorf("Method = %q, want %q", r.Method, tt.method)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("header=" + got))
			}))
			defer server.Close()

			client := NewClient()
			resp, err := client.SendPayloadInHeader(context.Background(), server.URL, tt.headerName, tt.payload, tt.method)

			if err != nil {
				t.Fatalf("SendPayloadInHeader() error = %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			if resp.Body != "header="+tt.payload {
				t.Errorf("Body = %q, want %q", resp.Body, "header="+tt.payload)
			}
		})
	}
}

func TestClient_SendPayloadInHeader_InvalidURL(t *testing.T) {
	client := NewClient()
	_, err := client.SendPayloadInHeader(context.Background(), "://invalid", "X-Test", "payload", "GET")
	if err == nil {
		t.Error("SendPayloadInHeader() should return error for invalid URL")
	}
}

func TestClient_SendPayloadInCookie(t *testing.T) {
	tests := []struct {
		name       string
		cookieName string
		payload    string
		method     string
	}{
		{
			name:       "inject into session cookie",
			cookieName: "session",
			payload:    "abc123",
			method:     "GET",
		},
		{
			name:       "inject SQL payload into cookie",
			cookieName: "user_id",
			payload:    "1' OR '1'='1",
			method:     "POST",
		},
		{
			name:       "inject XSS payload into cookie",
			cookieName: "token",
			payload:    "<script>alert(1)</script>",
			method:     "GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cookie := r.Header.Get("Cookie")
				expected := tt.cookieName + "=" + tt.payload
				if cookie != expected {
					t.Errorf("Cookie = %q, want %q", cookie, expected)
				}
				if r.Method != tt.method {
					t.Errorf("Method = %q, want %q", r.Method, tt.method)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}))
			defer server.Close()

			client := NewClient()
			resp, err := client.SendPayloadInCookie(context.Background(), server.URL, tt.cookieName, tt.payload, tt.method)

			if err != nil {
				t.Fatalf("SendPayloadInCookie() error = %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
			}
		})
	}
}

func TestClient_SendPayloadInCookie_InvalidURL(t *testing.T) {
	client := NewClient()
	_, err := client.SendPayloadInCookie(context.Background(), "://invalid", "session", "payload", "GET")
	if err == nil {
		t.Error("SendPayloadInCookie() should return error for invalid URL")
	}
}

func TestClient_SendPayloadInJSON(t *testing.T) {
	tests := []struct {
		name       string
		fieldPath  string
		payload    string
		wantBody   string
	}{
		{
			name:      "inject into simple field",
			fieldPath: "username",
			payload:   "admin",
			wantBody:  `{"username":"admin"}`,
		},
		{
			name:      "inject SQL payload into field",
			fieldPath: "search",
			payload:   "' OR 1=1 --",
			wantBody:  `{"search":"' OR 1=1 --"}`,
		},
		{
			name:      "inject into id field",
			fieldPath: "id",
			payload:   "12345",
			wantBody:  `{"id":"12345"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedBody string
			var receivedContentType string
			var receivedMethod string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedMethod = r.Method
				receivedContentType = r.Header.Get("Content-Type")
				bodyBytes, _ := io.ReadAll(r.Body)
				receivedBody = string(bodyBytes)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}))
			defer server.Close()

			client := NewClient()
			resp, err := client.SendPayloadInJSON(context.Background(), server.URL, tt.fieldPath, tt.payload)

			if err != nil {
				t.Fatalf("SendPayloadInJSON() error = %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			if receivedMethod != http.MethodPost {
				t.Errorf("Method = %q, want POST", receivedMethod)
			}
			if receivedContentType != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", receivedContentType)
			}
			if receivedBody != tt.wantBody {
				t.Errorf("Body = %q, want %q", receivedBody, tt.wantBody)
			}
		})
	}
}

func TestClient_SendPayloadInJSON_InvalidURL(t *testing.T) {
	client := NewClient()
	_, err := client.SendPayloadInJSON(context.Background(), "://invalid", "field", "payload")
	if err == nil {
		t.Error("SendPayloadInJSON() should return error for invalid URL")
	}
}

func TestClient_SendPayloadInPath(t *testing.T) {
	tests := []struct {
		name         string
		basePath     string
		segmentIndex int
		payload      string
		method       string
		wantPath     string
	}{
		{
			name:         "replace second path segment",
			basePath:     "/users/123/profile",
			segmentIndex: 1,
			payload:      "456",
			method:       "GET",
			wantPath:     "/users/456/profile",
		},
		{
			name:         "replace first path segment",
			basePath:     "/api/v1/items",
			segmentIndex: 0,
			payload:      "evil",
			method:       "GET",
			wantPath:     "/evil/v1/items",
		},
		{
			name:         "replace last path segment",
			basePath:     "/a/b/c",
			segmentIndex: 2,
			payload:      "injected",
			method:       "POST",
			wantPath:     "/a/b/injected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				if r.Method != tt.method {
					t.Errorf("Method = %q, want %q", r.Method, tt.method)
				}
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("path=" + r.URL.Path))
			}))
			defer server.Close()

			client := NewClient()
			resp, err := client.SendPayloadInPath(context.Background(), server.URL+tt.basePath, tt.segmentIndex, tt.payload, tt.method)

			if err != nil {
				t.Fatalf("SendPayloadInPath() error = %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			if receivedPath != tt.wantPath {
				t.Errorf("Path = %q, want %q", receivedPath, tt.wantPath)
			}
		})
	}
}

func TestClient_SendPayloadInPath_InvalidURL(t *testing.T) {
	client := NewClient()
	_, err := client.SendPayloadInPath(context.Background(), "://invalid", 0, "payload", "GET")
	if err == nil {
		t.Error("SendPayloadInPath() should return error for invalid URL")
	}
}

func TestClient_SendPayloadInPath_IndexOutOfRange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient()
	_, err := client.SendPayloadInPath(context.Background(), server.URL+"/a/b", 5, "payload", "GET")
	if err == nil {
		t.Error("SendPayloadInPath() should return error for out-of-range segment index")
	}
}

func TestClient_SendPayloadInPath_NegativeIndex(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewClient()
	_, err := client.SendPayloadInPath(context.Background(), server.URL+"/a/b", -1, "payload", "GET")
	if err == nil {
		t.Error("SendPayloadInPath() should return error for negative segment index")
	}
}

func TestClient_SendPayloadInXML(t *testing.T) {
	tests := []struct {
		name        string
		elementName string
		payload     string
		wantBody    string
	}{
		{
			name:        "inject into username element",
			elementName: "username",
			payload:     "admin",
			wantBody:    "<username>admin</username>",
		},
		{
			name:        "inject XXE payload",
			elementName: "data",
			payload:     "test-value",
			wantBody:    "<data>test-value</data>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedBody string
			var receivedContentType string
			var receivedMethod string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedMethod = r.Method
				receivedContentType = r.Header.Get("Content-Type")
				bodyBytes, _ := io.ReadAll(r.Body)
				receivedBody = string(bodyBytes)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok"))
			}))
			defer server.Close()

			client := NewClient()
			resp, err := client.SendPayloadInXML(context.Background(), server.URL, tt.elementName, tt.payload)

			if err != nil {
				t.Fatalf("SendPayloadInXML() error = %v", err)
			}
			if resp.StatusCode != http.StatusOK {
				t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			if receivedMethod != http.MethodPost {
				t.Errorf("Method = %q, want POST", receivedMethod)
			}
			if receivedContentType != "text/xml" {
				t.Errorf("Content-Type = %q, want text/xml", receivedContentType)
			}
			if receivedBody != tt.wantBody {
				t.Errorf("Body = %q, want %q", receivedBody, tt.wantBody)
			}
		})
	}
}

func TestClient_SendPayloadInXML_InvalidURL(t *testing.T) {
	client := NewClient()
	_, err := client.SendPayloadInXML(context.Background(), "://invalid", "element", "payload")
	if err == nil {
		t.Error("SendPayloadInXML() should return error for invalid URL")
	}
}

func TestClient_SendPayload_POST_BodyOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For POST, the payload should be in the body, NOT in the query string
		queryVal := r.URL.Query().Get("id")
		if queryVal != "" {
			t.Errorf("POST should not have payload in query string, got id=%q", queryVal)
		}
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)
		if !strings.Contains(body, "id=injected") {
			t.Errorf("POST body should contain id=injected, got %q", body)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := NewClient()
	resp, err := client.SendPayload(context.Background(), server.URL+"?id=original", "id", "injected", "POST")

	if err != nil {
		t.Fatalf("SendPayload() POST error = %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestClient_SendPayload_PUT_BodyOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryVal := r.URL.Query().Get("id")
		if queryVal != "" {
			t.Errorf("PUT should not have payload in query string, got id=%q", queryVal)
		}
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)
		if !strings.Contains(body, "id=injected") {
			t.Errorf("PUT body should contain id=injected, got %q", body)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := NewClient()
	_, err := client.SendPayload(context.Background(), server.URL+"?id=original", "id", "injected", "PUT")
	if err != nil {
		t.Fatalf("SendPayload() PUT error = %v", err)
	}
}
