package http

import (
	"context"
	"net/http"
	"net/http/httptest"
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
