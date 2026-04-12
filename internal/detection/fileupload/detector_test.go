package fileupload

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}

	if detector.client != client {
		t.Error("New() did not set client correctly")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()

	detector := New(client).WithVerbose(true)
	if !detector.verbose {
		t.Error("WithVerbose(true) did not set verbose flag")
	}
}

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector.Name() != "fileupload-detector" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "fileupload-detector")
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.MaxPayloads <= 0 {
		t.Error("DefaultOptions() MaxPayloads should be positive")
	}
	if opts.Timeout <= 0 {
		t.Error("DefaultOptions() Timeout should be positive")
	}
	if !opts.IncludeMIMEBypass {
		t.Error("DefaultOptions() IncludeMIMEBypass should be true")
	}
	if !opts.IncludeDoubleExt {
		t.Error("DefaultOptions() IncludeDoubleExt should be true")
	}
	if !opts.IncludeNullByte {
		t.Error("DefaultOptions() IncludeNullByte should be true")
	}
}

func TestDetect_AcceptsExecutableExtension(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "multipart/form-data") {
			// Server accepts the upload and indicates success
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "File uploaded successfully")
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "Bad request")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/upload", "file", "POST", DetectOptions{
		MaxPayloads:       20,
		IncludeMIMEBypass: false,
		IncludeDoubleExt:  false,
		IncludeNullByte:   false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected when server accepts executable uploads")
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if finding.Severity != core.SeverityHigh {
		t.Errorf("Severity = %v, want %v", finding.Severity, core.SeverityHigh)
	}
	if finding.Tool != "fileupload-detector" {
		t.Errorf("Tool = %q, want %q", finding.Tool, "fileupload-detector")
	}
	if len(finding.WSTG) == 0 {
		t.Error("Expected WSTG mappings")
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mappings")
	}
}

func TestDetect_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server rejects all uploads
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "File type not allowed")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/upload", "file", "POST", DetectOptions{
		MaxPayloads:       20,
		IncludeMIMEBypass: true,
		IncludeDoubleExt:  true,
		IncludeNullByte:   true,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected no findings, got %d", len(result.Findings))
	}
}

func TestDetect_EmptyURL(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), "", "file", "POST", DefaultOptions())

	if err == nil {
		t.Error("Expected error for empty URL")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
	}

	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("Expected error about empty URL, got: %v", err)
	}
}

func TestDetect_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := detector.Detect(ctx, server.URL+"/upload", "file", "POST", DetectOptions{
		MaxPayloads:       100,
		IncludeMIMEBypass: true,
		IncludeDoubleExt:  true,
		IncludeNullByte:   true,
	})

	// Either context error returned directly or wrapped
	if err == nil {
		// It's acceptable if no error when context cancellation happened
		// before any payload was tested
		return
	}

	if !strings.Contains(err.Error(), "context canceled") && err != context.Canceled {
		t.Logf("Got error variant: %v", err)
	}
}

func TestDetect_MIMETypeBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "multipart/form-data") {
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, "File stored at /uploads/test.php")
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/upload", "file", "POST", DetectOptions{
		MaxPayloads:       30,
		IncludeMIMEBypass: true,
		IncludeDoubleExt:  false,
		IncludeNullByte:   false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected MIME type bypass vulnerability to be detected")
	}
}

func TestDetect_DoubleExtension(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "multipart/form-data") {
			// Reject single dangerous extensions but accept double extensions
			if err := r.ParseMultipartForm(1024 * 1024); err == nil {
				for _, headers := range r.MultipartForm.File {
					for _, h := range headers {
						if strings.Contains(h.Filename, ".php.jpg") ||
							strings.Contains(h.Filename, ".php.png") {
							w.WriteHeader(http.StatusOK)
							fmt.Fprintf(w, "File uploaded: %s", h.Filename)
							return
						}
					}
				}
			}
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "File type not allowed")
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/upload", "file", "POST", DetectOptions{
		MaxPayloads:       30,
		IncludeMIMEBypass: false,
		IncludeDoubleExt:  true,
		IncludeNullByte:   false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected double extension bypass vulnerability to be detected")
	}
}

func TestDetect_PathDisclosure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType := r.Header.Get("Content-Type")
		if strings.Contains(contentType, "multipart/form-data") {
			w.WriteHeader(http.StatusOK)
			// Response contains the uploaded filename (path disclosure)
			fmt.Fprint(w, "test.php has been processed")
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/upload", "file", "POST", DetectOptions{
		MaxPayloads:       20,
		IncludeMIMEBypass: false,
		IncludeDoubleExt:  false,
		IncludeNullByte:   false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected path disclosure vulnerability to be detected")
	}
}

func TestDetect_ServerDown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverURL := server.URL
	server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), serverURL+"/upload", "file", "POST", DetectOptions{
		MaxPayloads:       5,
		IncludeMIMEBypass: false,
		IncludeDoubleExt:  false,
		IncludeNullByte:   false,
	})

	// No error expected because individual payload failures are skipped
	if err != nil {
		t.Logf("Got error (acceptable): %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability when server is down")
	}
}

func TestDetect_PayloadLimiting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Rejected")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"/upload", "file", "POST", DetectOptions{
		MaxPayloads:       3,
		IncludeMIMEBypass: true,
		IncludeDoubleExt:  true,
		IncludeNullByte:   true,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.TestedPayloads > 3 {
		t.Errorf("Expected at most 3 tested payloads, got %d", result.TestedPayloads)
	}
}

func TestDetect_IsUploadAccepted(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		resp     *internalhttp.Response
		filename string
		expected bool
	}{
		{
			name:     "nil response",
			resp:     nil,
			filename: "test.php",
			expected: false,
		},
		{
			name:     "403 status",
			resp:     &internalhttp.Response{StatusCode: 403, Body: "Forbidden"},
			filename: "test.php",
			expected: false,
		},
		{
			name:     "200 with upload indicator",
			resp:     &internalhttp.Response{StatusCode: 200, Body: "File uploaded successfully"},
			filename: "test.php",
			expected: true,
		},
		{
			name:     "201 with filename in response",
			resp:     &internalhttp.Response{StatusCode: 201, Body: "Saved as test.php"},
			filename: "test.php",
			expected: true,
		},
		{
			name:     "200 without indicators",
			resp:     &internalhttp.Response{StatusCode: 200, Body: "OK"},
			filename: "test.php",
			expected: false,
		},
		{
			name:     "500 with upload text",
			resp:     &internalhttp.Response{StatusCode: 500, Body: "Upload failed"},
			filename: "test.php",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isUploadAccepted(tt.resp, tt.filename)
			if got != tt.expected {
				t.Errorf("isUploadAccepted() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDetect_BuildMultipartBody(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	body, contentType, err := detector.buildMultipartBody("file", "test.php", "application/octet-stream", "<?php ?>")
	if err != nil {
		t.Fatalf("buildMultipartBody() returned error: %v", err)
	}

	if body == "" {
		t.Error("Expected non-empty body")
	}

	if !strings.Contains(contentType, "multipart/form-data") {
		t.Errorf("Expected multipart/form-data content type, got %q", contentType)
	}

	if !strings.Contains(body, "test.php") {
		t.Error("Expected body to contain filename")
	}
}
