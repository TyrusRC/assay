package xxe

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/payloads/xxe"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// newTestDetector creates a Detector with the given HTTP client for tests.
func newTestDetector(client *internalhttp.Client) *Detector {
	return New(client)
}

// newMockServer creates an httptest.Server that responds with the given body
// and status code for every request.
func newMockServer(statusCode int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(statusCode)
		fmt.Fprint(w, body)
	}))
}

// newRoutingMockServer returns different responses based on the request body.
// If the body contains the baseline XML it returns baselineBody; otherwise it
// returns payloadBody.
func newRoutingMockServer(baselineBody, payloadBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		reqBody := string(buf[:n])
		w.Header().Set("Content-Type", "application/xml")
		if strings.Contains(reqBody, "baseline") {
			fmt.Fprint(w, baselineBody)
		} else {
			fmt.Fprint(w, payloadBody)
		}
	}))
}

// newQueryRoutingMockServer routes based on the "xml" query parameter value.
// Baseline requests contain the word "baseline", payload requests do not.
func newQueryRoutingMockServer(baselineBody, payloadBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		xmlParam := r.URL.Query().Get("xml")
		if strings.Contains(xmlParam, "baseline") {
			fmt.Fprint(w, baselineBody)
		} else {
			fmt.Fprint(w, payloadBody)
		}
	}))
}

// ---------------------------------------------------------------------------
// TestNew
// ---------------------------------------------------------------------------

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	if d == nil {
		t.Fatal("New() returned nil")
	}
	if d.client != client {
		t.Error("New() did not assign client")
	}
	if len(d.contentPatterns) == 0 {
		t.Error("New() did not initialize content patterns")
	}
	if len(d.errorPatterns) == 0 {
		t.Error("New() did not initialize error patterns")
	}
}

// ---------------------------------------------------------------------------
// TestWithVerbose
// ---------------------------------------------------------------------------

func TestWithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	if d.verbose {
		t.Error("verbose should default to false")
	}

	d2 := d.WithVerbose(true)
	if !d2.verbose {
		t.Error("WithVerbose(true) did not set verbose")
	}
	if d2 != d {
		t.Error("WithVerbose should return the same receiver for chaining")
	}

	d.WithVerbose(false)
	if d.verbose {
		t.Error("WithVerbose(false) did not clear verbose")
	}
}

// ---------------------------------------------------------------------------
// TestDefaultOptions
// ---------------------------------------------------------------------------

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.MaxPayloads != 20 {
		t.Errorf("DefaultOptions().MaxPayloads = %d, want 20", opts.MaxPayloads)
	}
	if opts.Timeout != 10*time.Second {
		t.Errorf("DefaultOptions().Timeout = %v, want 10s", opts.Timeout)
	}
	if opts.ContentType != "application/xml" {
		t.Errorf("DefaultOptions().ContentType = %q, want application/xml", opts.ContentType)
	}
	if opts.TargetParser != xxe.ParserGeneric {
		t.Errorf("DefaultOptions().TargetParser = %q, want generic", opts.TargetParser)
	}
	if len(opts.TestTypes) != 2 {
		t.Fatalf("DefaultOptions().TestTypes has %d entries, want 2", len(opts.TestTypes))
	}
	if opts.TestTypes[0] != xxe.TypeClassic {
		t.Errorf("DefaultOptions().TestTypes[0] = %q, want classic", opts.TestTypes[0])
	}
	if opts.TestTypes[1] != xxe.TypeErrorBased {
		t.Errorf("DefaultOptions().TestTypes[1] = %q, want error", opts.TestTypes[1])
	}
}

// ---------------------------------------------------------------------------
// TestCheckXXESuccess
// ---------------------------------------------------------------------------

func TestCheckXXESuccess(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	dummyPayload := xxe.Payload{
		Type:        xxe.TypeClassic,
		Target:      xxe.TargetFileRead,
		Parser:      xxe.ParserGeneric,
		Description: "test",
	}

	tests := []struct {
		name           string
		respBody       string
		baselineBody   string
		nilBaseline    bool
		nilResp        bool
		wantSuccess    bool
		wantDataEmpty  bool
	}{
		{
			name:          "nil response returns false",
			nilResp:       true,
			wantSuccess:   false,
			wantDataEmpty: true,
		},
		{
			name:          "passwd content detected - not in baseline",
			respBody:      "<result>root:x:0:0:root:/root:/bin/bash</result>",
			baselineBody:  "<result>OK</result>",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "passwd content detected - nil baseline",
			respBody:      "<result>root:x:0:0:root:/root:/bin/bash</result>",
			nilBaseline:   true,
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "passwd content already in baseline - skip",
			respBody:      "root:x:0:0:root:/root:/bin/bash",
			baselineBody:  "root:x:0:0:root:/root:/bin/bash",
			wantSuccess:   false,
			wantDataEmpty: true,
		},
		{
			name:          "hosts content detected",
			respBody:      "127.0.0.1\tlocalhost",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "windows ini content detected",
			respBody:      "[fonts]\nCourier=something",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "aws metadata detected",
			respBody:      "ami-0abcdef1234567890",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "instance-id detected",
			respBody:      "instance-id: i-1234567890",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "PATH env var detected",
			respBody:      "PATH=/usr/bin:/bin",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "HOME env var detected",
			respBody:      "HOME=/root",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "private key detected",
			respBody:      "-----BEGIN RSA KEY-----\nabc",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "daemon line detected",
			respBody:      "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "nobody line detected",
			respBody:      "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "ipv6 localhost detected",
			respBody:      "::1\tlocalhost",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "extensions ini detected",
			respBody:      "[extensions]\nfoo=bar",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "mci extensions ini detected",
			respBody:      "[mci extensions]\nfoo=bar",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: false,
		},
		{
			name:          "error - failed to load external entity",
			respBody:      "Error: failed to load external entity",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - error loading external entity",
			respBody:      "Error loading external entity /etc/passwd",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - connection refused",
			respBody:      "Error: connection refused",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - name resolution failed",
			respBody:      "name resolution failed for evil.com",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - could not resolve host",
			respBody:      "could not resolve host evil.com",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - network unreachable",
			respBody:      "network unreachable",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - permission denied",
			respBody:      "permission denied for /etc/shadow",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - no such file",
			respBody:      "no such file or directory",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - failed to open",
			respBody:      "failed to open stream /etc/passwd",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - file not found",
			respBody:      "file not found /etc/passwd",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - SYSTEM entity reference",
			respBody:      "SYSTEM entity reference detected",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - DTD not allowed",
			respBody:      "DTD is not allowed in this context",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - DOCTYPE disallowed",
			respBody:      "DOCTYPE is disallowed",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - entity expansion",
			respBody:      "entity expansion detected",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error - recursive entity",
			respBody:      "recursive entity reference detected",
			baselineBody:  "OK",
			wantSuccess:   true,
			wantDataEmpty: true,
		},
		{
			name:          "error pattern already in baseline - skip",
			respBody:      "Error: connection refused",
			baselineBody:  "Error: connection refused",
			wantSuccess:   false,
			wantDataEmpty: true,
		},
		{
			name:          "clean response - no indicators",
			respBody:      "<result>all good</result>",
			baselineBody:  "<result>all good</result>",
			wantSuccess:   false,
			wantDataEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *internalhttp.Response
			if !tt.nilResp {
				resp = &internalhttp.Response{Body: tt.respBody}
			}

			var baseline *internalhttp.Response
			if !tt.nilBaseline && !tt.nilResp {
				baseline = &internalhttp.Response{Body: tt.baselineBody}
			}

			success, data := d.checkXXESuccess(resp, baseline, dummyPayload)

			if success != tt.wantSuccess {
				t.Errorf("checkXXESuccess() success = %v, want %v", success, tt.wantSuccess)
			}
			if tt.wantDataEmpty && data != "" {
				t.Errorf("checkXXESuccess() data = %q, want empty", data)
			}
			if !tt.wantDataEmpty && data == "" {
				t.Errorf("checkXXESuccess() data is empty, want non-empty")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestCheckXXESuccess_SignificantDifference
// ---------------------------------------------------------------------------

func TestCheckXXESuccess_SignificantDifference(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	dummyPayload := xxe.Payload{
		Type:   xxe.TypeClassic,
		Target: xxe.TargetFileRead,
		Parser: xxe.ParserGeneric,
	}

	tests := []struct {
		name        string
		respBody    string
		baseline    string
		wantSuccess bool
	}{
		{
			name:        "significantly different with file content (root:)",
			respBody:    "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/sbin/nologin",
			baseline:    "OK",
			wantSuccess: true,
		},
		{
			name:        "significantly different with localhost",
			respBody:    "127.0.0.1 localhost\n::1 ip6-localhost",
			baseline:    "X",
			wantSuccess: true,
		},
		{
			name:        "significantly different but no file content",
			respBody:    strings.Repeat("A", 300),
			baseline:    strings.Repeat("B", 100),
			wantSuccess: false,
		},
		{
			name:        "same length same prefix no indicators",
			respBody:    strings.Repeat("A", 150),
			baseline:    strings.Repeat("A", 150),
			wantSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &internalhttp.Response{Body: tt.respBody}
			base := &internalhttp.Response{Body: tt.baseline}
			success, _ := d.checkXXESuccess(resp, base, dummyPayload)
			if success != tt.wantSuccess {
				t.Errorf("checkXXESuccess() = %v, want %v", success, tt.wantSuccess)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestSignificantlyDifferent
// ---------------------------------------------------------------------------

func TestSignificantlyDifferent(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	tests := []struct {
		name     string
		body1    string
		body2    string
		expected bool
	}{
		{
			name:     "same short content",
			body1:    "Hello World",
			body2:    "Hello World",
			expected: false,
		},
		{
			name:     "very different length - body1 longer",
			body1:    "This is a much longer response that contains a lot more data",
			body2:    "Short",
			expected: true,
		},
		{
			name:     "very different length - body2 longer",
			body1:    "Short",
			body2:    "This is a much longer response that contains a lot more data",
			expected: true,
		},
		{
			name:     "different short content",
			body1:    "Response A",
			body2:    "Response B",
			expected: true,
		},
		{
			name:     "both empty",
			body1:    "",
			body2:    "",
			expected: false,
		},
		{
			name:     "one empty one short",
			body1:    "",
			body2:    "hello",
			expected: true,
		},
		{
			name:     "long strings same prefix different content",
			body1:    strings.Repeat("A", 100) + strings.Repeat("B", 50),
			body2:    strings.Repeat("A", 100) + strings.Repeat("C", 50),
			expected: false,
		},
		{
			name:     "long strings different prefix",
			body1:    "X" + strings.Repeat("A", 149),
			body2:    "Y" + strings.Repeat("A", 149),
			expected: true,
		},
		{
			name:     "exactly 100 chars same",
			body1:    strings.Repeat("Z", 100),
			body2:    strings.Repeat("Z", 100),
			expected: false,
		},
		{
			name:     "exactly 100 chars different first char",
			body1:    "A" + strings.Repeat("Z", 99),
			body2:    "B" + strings.Repeat("Z", 99),
			expected: true,
		},
		{
			name:     "just under 100 chars different",
			body1:    strings.Repeat("A", 99),
			body2:    strings.Repeat("B", 99),
			expected: true,
		},
		{
			name:     "body1 double body2 length boundary - different prefix",
			body1:    strings.Repeat("A", 200),
			body2:    strings.Repeat("B", 100),
			expected: true,
		},
		{
			name:     "body1 just over double body2 length",
			body1:    strings.Repeat("A", 201),
			body2:    strings.Repeat("B", 100),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.significantlyDifferent(tt.body1, tt.body2)
			if result != tt.expected {
				t.Errorf("significantlyDifferent(%d chars, %d chars) = %v, want %v",
					len(tt.body1), len(tt.body2), result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestHasFileContent
// ---------------------------------------------------------------------------

func TestHasFileContent(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{name: "root: indicator", content: "root:x:0:0", expected: true},
		{name: "daemon: indicator", content: "daemon:x:1:1", expected: true},
		{name: "nobody: indicator", content: "nobody:x:65534", expected: true},
		{name: "127.0.0.1 indicator", content: "127.0.0.1 myhost", expected: true},
		{name: "localhost indicator", content: "this is localhost data", expected: true},
		{name: "[fonts] indicator", content: "[fonts]\nCourier=courier.ttf", expected: true},
		{name: "[extensions] indicator", content: "[extensions]\n.txt=txtfile", expected: true},
		{name: "PATH= indicator", content: "PATH=/usr/bin:/bin", expected: true},
		{name: "HOME= indicator", content: "HOME=/home/user", expected: true},
		{name: "USER= indicator", content: "USER=root", expected: true},
		{name: "-----BEGIN indicator", content: "-----BEGIN RSA PRIVATE KEY-----", expected: true},
		{name: "normal HTML", content: "<html><body>Welcome</body></html>", expected: false},
		{name: "empty string", content: "", expected: false},
		{name: "random text", content: "Lorem ipsum dolor sit amet", expected: false},
		{name: "JSON response", content: `{"status": "ok", "code": 200}`, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.hasFileContent(tt.content)
			if result != tt.expected {
				t.Errorf("hasFileContent(%q) = %v, want %v", tt.content, result, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestInitPatterns
// ---------------------------------------------------------------------------

func TestInitPatterns(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	t.Run("content patterns are compiled", func(t *testing.T) {
		if len(d.contentPatterns) == 0 {
			t.Fatal("no content patterns initialized")
		}
		for i, p := range d.contentPatterns {
			if p == nil {
				t.Errorf("contentPatterns[%d] is nil", i)
			}
		}
	})

	t.Run("error patterns are compiled", func(t *testing.T) {
		if len(d.errorPatterns) == 0 {
			t.Fatal("no error patterns initialized")
		}
		for i, p := range d.errorPatterns {
			if p == nil {
				t.Errorf("errorPatterns[%d] is nil", i)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// TestCreateFinding
// ---------------------------------------------------------------------------

func TestCreateFinding(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	tests := []struct {
		name             string
		target           string
		payload          xxe.Payload
		respBody         string
		extractedData    string
		wantSeverity     core.Severity
		wantToolField    string
		wantHasEvidence  bool
		wantHasSnippet   bool
		wantRemediation  bool
		wantOWASP        bool
	}{
		{
			name:   "file read payload - high severity",
			target: "http://example.com/api",
			payload: xxe.Payload{
				Type:        xxe.TypeClassic,
				Target:      xxe.TargetFileRead,
				Parser:      xxe.ParserGeneric,
				Description: "Basic file read /etc/passwd",
			},
			respBody:        "root:x:0:0:root:/root:/bin/bash",
			extractedData:   "root:x:0:0:",
			wantSeverity:    core.SeverityHigh,
			wantToolField:   "xxe-detector",
			wantHasEvidence: true,
			wantHasSnippet:  true,
			wantRemediation: true,
			wantOWASP:       true,
		},
		{
			name:   "RCE payload - critical severity",
			target: "http://example.com/api",
			payload: xxe.Payload{
				Type:        xxe.TypeBlind,
				Target:      xxe.TargetRCE,
				Parser:      xxe.ParserPHP,
				Description: "PHP expect RCE",
			},
			respBody:        "uid=0(root)",
			extractedData:   "",
			wantSeverity:    core.SeverityCritical,
			wantToolField:   "xxe-detector",
			wantHasEvidence: true,
			wantHasSnippet:  true,
			wantRemediation: true,
			wantOWASP:       true,
		},
		{
			name:   "SSRF payload - high severity",
			target: "http://example.com/api",
			payload: xxe.Payload{
				Type:        xxe.TypeClassic,
				Target:      xxe.TargetSSRF,
				Parser:      xxe.ParserGeneric,
				Description: "AWS metadata SSRF",
			},
			respBody:        "ami-0abcdef1234567890",
			extractedData:   "ami-0abcdef1234567890",
			wantSeverity:    core.SeverityHigh,
			wantToolField:   "xxe-detector",
			wantHasEvidence: true,
			wantHasSnippet:  true,
			wantRemediation: true,
			wantOWASP:       true,
		},
		{
			name:   "no extracted data",
			target: "http://example.com/api",
			payload: xxe.Payload{
				Type:        xxe.TypeErrorBased,
				Target:      xxe.TargetFileRead,
				Parser:      xxe.ParserGeneric,
				Description: "Error-based exfiltration",
			},
			respBody:        "failed to load external entity",
			extractedData:   "",
			wantSeverity:    core.SeverityHigh,
			wantToolField:   "xxe-detector",
			wantHasEvidence: true,
			wantHasSnippet:  true,
			wantRemediation: true,
			wantOWASP:       true,
		},
		{
			name:   "nil response body",
			target: "http://example.com/api",
			payload: xxe.Payload{
				Type:        xxe.TypeClassic,
				Target:      xxe.TargetFileRead,
				Parser:      xxe.ParserGeneric,
				Description: "test",
			},
			respBody:        "",
			extractedData:   "",
			wantSeverity:    core.SeverityHigh,
			wantToolField:   "xxe-detector",
			wantHasEvidence: true,
			wantHasSnippet:  false,
			wantRemediation: true,
			wantOWASP:       true,
		},
		{
			name:   "long response body is truncated",
			target: "http://example.com/api",
			payload: xxe.Payload{
				Type:        xxe.TypeClassic,
				Target:      xxe.TargetFileRead,
				Parser:      xxe.ParserGeneric,
				Description: "test",
			},
			respBody:        strings.Repeat("A", 600),
			extractedData:   "data",
			wantSeverity:    core.SeverityHigh,
			wantToolField:   "xxe-detector",
			wantHasEvidence: true,
			wantHasSnippet:  true,
			wantRemediation: true,
			wantOWASP:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var resp *internalhttp.Response
			if tt.respBody != "" || tt.wantHasSnippet {
				resp = &internalhttp.Response{Body: tt.respBody}
			}

			finding := d.createFinding(tt.target, tt.payload, resp, tt.extractedData)

			if finding == nil {
				t.Fatal("createFinding returned nil")
			}
			if finding.Severity != tt.wantSeverity {
				t.Errorf("severity = %q, want %q", finding.Severity, tt.wantSeverity)
			}
			if finding.Tool != tt.wantToolField {
				t.Errorf("tool = %q, want %q", finding.Tool, tt.wantToolField)
			}
			if finding.URL != tt.target {
				t.Errorf("URL = %q, want %q", finding.URL, tt.target)
			}
			if finding.Type != "XML External Entity (XXE) Injection" {
				t.Errorf("Type = %q, want 'XML External Entity (XXE) Injection'", finding.Type)
			}
			if finding.Description == "" {
				t.Error("Description is empty")
			}
			if tt.wantHasEvidence && finding.Evidence == "" {
				t.Error("Evidence is empty")
			}
			if tt.extractedData != "" && !strings.Contains(finding.Evidence, tt.extractedData) {
				t.Error("Evidence does not contain extracted data")
			}
			if tt.wantRemediation && finding.Remediation == "" {
				t.Error("Remediation is empty")
			}
			if tt.wantOWASP {
				if len(finding.WSTG) == 0 {
					t.Error("WSTG mapping is empty")
				}
				if len(finding.Top10) == 0 {
					t.Error("Top10 mapping is empty")
				}
				if len(finding.CWE) == 0 {
					t.Error("CWE mapping is empty")
				}
			}
			// Check snippet truncation for long bodies
			if len(tt.respBody) > 500 && !strings.Contains(finding.Evidence, "...") {
				t.Error("long response body should be truncated with '...'")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestCreateFinding_NilResponse
// ---------------------------------------------------------------------------

func TestCreateFinding_NilResponse(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	payload := xxe.Payload{
		Type:        xxe.TypeClassic,
		Target:      xxe.TargetFileRead,
		Parser:      xxe.ParserGeneric,
		Description: "test",
	}

	finding := d.createFinding("http://example.com", payload, nil, "")
	if finding == nil {
		t.Fatal("createFinding with nil response returned nil")
	}
	if finding.Severity != core.SeverityHigh {
		t.Errorf("severity = %q, want high", finding.Severity)
	}
}

// ---------------------------------------------------------------------------
// TestCreateFindingWithParam
// ---------------------------------------------------------------------------

func TestCreateFindingWithParam(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	payload := xxe.Payload{
		Type:        xxe.TypeClassic,
		Target:      xxe.TargetFileRead,
		Parser:      xxe.ParserGeneric,
		Description: "test",
	}

	resp := &internalhttp.Response{Body: "root:x:0:0:root"}
	finding := d.createFindingWithParam("http://example.com/api", "xmlInput", payload, resp, "root:x:0:0:")

	if finding == nil {
		t.Fatal("createFindingWithParam returned nil")
	}
	if finding.Parameter != "xmlInput" {
		t.Errorf("Parameter = %q, want 'xmlInput'", finding.Parameter)
	}
	if !strings.Contains(finding.Description, "xmlInput") {
		t.Error("Description should mention the parameter name")
	}
	if !strings.Contains(finding.Description, string(xxe.TypeClassic)) {
		t.Error("Description should mention the XXE type")
	}
}

// ---------------------------------------------------------------------------
// TestSendXMLPayload
// ---------------------------------------------------------------------------

func TestSendXMLPayload(t *testing.T) {
	ts := newMockServer(200, "<response>OK</response>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)

	t.Run("successful POST", func(t *testing.T) {
		resp, err := d.sendXMLPayload(context.Background(), ts.URL, "POST", "<test/>", "application/xml")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("response is nil")
		}
		if resp.Body != "<response>OK</response>" {
			t.Errorf("body = %q, want '<response>OK</response>'", resp.Body)
		}
	})

	t.Run("successful GET", func(t *testing.T) {
		resp, err := d.sendXMLPayload(context.Background(), ts.URL, "GET", "<test/>", "text/xml")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp == nil {
			t.Fatal("response is nil")
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := d.sendXMLPayload(ctx, ts.URL, "POST", "<test/>", "application/xml")
		if err == nil {
			t.Error("expected error for cancelled context")
		}
	})

	t.Run("invalid URL", func(t *testing.T) {
		_, err := d.sendXMLPayload(context.Background(), "://invalid", "POST", "<test/>", "application/xml")
		if err == nil {
			t.Error("expected error for invalid URL")
		}
	})
}

// ---------------------------------------------------------------------------
// TestDetect_VulnerableTarget
// ---------------------------------------------------------------------------

func TestDetect_VulnerableTarget(t *testing.T) {
	// Server returns /etc/passwd content for any non-baseline request.
	ts := newRoutingMockServer(
		"<result>OK</result>",
		"<result>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/sbin/nologin</result>",
	)
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  5,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result == nil {
		t.Fatal("Detect() returned nil result")
	}
	if !result.Vulnerable {
		t.Error("expected Vulnerable = true")
	}
	if len(result.Findings) == 0 {
		t.Error("expected at least one finding")
	}
	if result.TestedPayloads == 0 {
		t.Error("expected TestedPayloads > 0")
	}
	if result.ExfiltratedData == "" {
		t.Error("expected ExfiltratedData to be non-empty")
	}
}

// ---------------------------------------------------------------------------
// TestDetect_NonVulnerableTarget
// ---------------------------------------------------------------------------

func TestDetect_NonVulnerableTarget(t *testing.T) {
	// Server always returns the same safe response.
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  3,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Vulnerable {
		t.Error("expected Vulnerable = false for safe target")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

// ---------------------------------------------------------------------------
// TestDetect_BaselineError
// ---------------------------------------------------------------------------

func TestDetect_BaselineError(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)
	opts := DefaultOptions()
	opts.MaxPayloads = 1

	// Use a URL that will fail to connect (port 0 should not be reachable).
	result, err := d.Detect(context.Background(), "http://127.0.0.1:0/test", "POST", opts)
	if err == nil {
		t.Error("expected error when baseline request fails")
	}
	if result == nil {
		t.Fatal("result should not be nil even on error")
	}
	if !strings.Contains(err.Error(), "failed to get baseline") {
		t.Errorf("error message should mention baseline failure, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestDetect_ContextCancellation
// ---------------------------------------------------------------------------

func TestDetect_ContextCancellation(t *testing.T) {
	// Slow server to allow cancellation between requests.
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		// Let the baseline through quickly, then slow down.
		if requestCount > 1 {
			time.Sleep(200 * time.Millisecond)
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "<result>OK</result>")
	}))
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	opts := DetectOptions{
		MaxPayloads:  50,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(ctx, ts.URL, "POST", opts)
	// Should get context error.
	if err == nil {
		// It is acceptable if we get no error and the function completed
		// before timeout, but in that case we should still have a result.
		if result == nil {
			t.Fatal("expected either an error or a result")
		}
	} else if !strings.Contains(err.Error(), "context") {
		t.Logf("got non-context error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestDetect_PayloadFilterByParser
// ---------------------------------------------------------------------------

func TestDetect_PayloadFilterByParser(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  100,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserPHP,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	// Filtering by PHP parser should test fewer payloads than the full set.
	allClassic := xxe.GetPayloads(xxe.TypeClassic)
	if result.TestedPayloads >= len(allClassic) {
		t.Logf("TestedPayloads=%d, allClassic=%d - PHP filter should reduce count or match if all are generic/php",
			result.TestedPayloads, len(allClassic))
	}
}

// ---------------------------------------------------------------------------
// TestDetect_MaxPayloadsLimit
// ---------------------------------------------------------------------------

func TestDetect_MaxPayloadsLimit(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  2,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic, xxe.TypeErrorBased},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.TestedPayloads > 2 {
		t.Errorf("TestedPayloads = %d, want <= 2 (MaxPayloads limit)", result.TestedPayloads)
	}
}

// ---------------------------------------------------------------------------
// TestDetect_MaxPayloadsZero
// ---------------------------------------------------------------------------

func TestDetect_MaxPayloadsZero(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  0,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	// MaxPayloads=0 means no limit, should test all classic payloads.
	allClassic := xxe.GetPayloads(xxe.TypeClassic)
	if result.TestedPayloads != len(allClassic) {
		t.Errorf("TestedPayloads = %d, want %d (no limit)", result.TestedPayloads, len(allClassic))
	}
}

// ---------------------------------------------------------------------------
// TestDetect_MultipleFindings_LimitTwo
// ---------------------------------------------------------------------------

func TestDetect_MultipleFindings_LimitTwo(t *testing.T) {
	// Server returns vulnerable content for every payload request.
	ts := newRoutingMockServer(
		"<result>OK</result>",
		"<result>root:x:0:0:root:/root:/bin/bash</result>",
	)
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  20,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic, xxe.TypeErrorBased},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("expected Vulnerable = true")
	}
	// Detection should stop after 2 findings.
	if len(result.Findings) > 2 {
		t.Errorf("expected at most 2 findings, got %d", len(result.Findings))
	}
}

// ---------------------------------------------------------------------------
// TestDetect_ErrorBasedPayloads
// ---------------------------------------------------------------------------

func TestDetect_ErrorBasedPayloads(t *testing.T) {
	ts := newRoutingMockServer(
		"<result>OK</result>",
		"Error: failed to load external entity '/etc/passwd'",
	)
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  5,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeErrorBased},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("expected Vulnerable = true for error-based XXE")
	}
	if result.DetectedType != xxe.TypeErrorBased {
		t.Errorf("DetectedType = %q, want %q", result.DetectedType, xxe.TypeErrorBased)
	}
}

// ---------------------------------------------------------------------------
// TestDetect_PayloadHTTPError
// ---------------------------------------------------------------------------

func TestDetect_PayloadHTTPError(t *testing.T) {
	// Server returns baseline OK but then closes connection for payloads.
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			// Baseline: return OK.
			w.WriteHeader(200)
			fmt.Fprint(w, "<result>OK</result>")
			return
		}
		// For subsequent requests: return OK (no error, just safe content).
		// This tests the "continue" path when sendXMLPayload succeeds but
		// checkXXESuccess returns false.
		w.WriteHeader(200)
		fmt.Fprint(w, "<result>OK</result>")
	}))
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  2,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if result.Vulnerable {
		t.Error("expected Vulnerable = false")
	}
}

// ---------------------------------------------------------------------------
// TestDetect_MultipleTestTypes
// ---------------------------------------------------------------------------

func TestDetect_MultipleTestTypes(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  100,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic, xxe.TypeErrorBased, xxe.TypeBlind},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}

	expectedTotal := len(xxe.GetPayloads(xxe.TypeClassic)) +
		len(xxe.GetPayloads(xxe.TypeErrorBased)) +
		len(xxe.GetPayloads(xxe.TypeBlind))
	if result.TestedPayloads != expectedTotal {
		t.Errorf("TestedPayloads = %d, want %d", result.TestedPayloads, expectedTotal)
	}
}

// ---------------------------------------------------------------------------
// TestDetectInParameter_VulnerableTarget
// ---------------------------------------------------------------------------

func TestDetectInParameter_VulnerableTarget(t *testing.T) {
	ts := newQueryRoutingMockServer(
		"<result>OK</result>",
		"<result>root:x:0:0:root:/root:/bin/bash</result>",
	)
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  5,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	targetURL := ts.URL + "/?xml=test"
	result, err := d.DetectInParameter(context.Background(), targetURL, "xml", "GET", opts)
	if err != nil {
		t.Fatalf("DetectInParameter() error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("expected Vulnerable = true")
	}
	if len(result.Findings) == 0 {
		t.Error("expected at least one finding")
	}
	if result.Findings[0].Parameter != "xml" {
		t.Errorf("finding parameter = %q, want 'xml'", result.Findings[0].Parameter)
	}
}

// ---------------------------------------------------------------------------
// TestDetectInParameter_NonVulnerableTarget
// ---------------------------------------------------------------------------

func TestDetectInParameter_NonVulnerableTarget(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  3,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	targetURL := ts.URL + "/?xml=test"
	result, err := d.DetectInParameter(context.Background(), targetURL, "xml", "GET", opts)
	if err != nil {
		t.Fatalf("DetectInParameter() error: %v", err)
	}
	if result.Vulnerable {
		t.Error("expected Vulnerable = false for safe target")
	}
}

// ---------------------------------------------------------------------------
// TestDetectInParameter_BaselineError
// ---------------------------------------------------------------------------

func TestDetectInParameter_BaselineError(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)
	opts := DefaultOptions()
	opts.MaxPayloads = 1

	result, err := d.DetectInParameter(context.Background(), "http://127.0.0.1:0/test?xml=test", "xml", "GET", opts)
	if err == nil {
		t.Error("expected error when baseline request fails")
	}
	if result == nil {
		t.Fatal("result should not be nil even on error")
	}
	if !strings.Contains(err.Error(), "failed to get baseline") {
		t.Errorf("error message should mention baseline failure, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TestDetectInParameter_ContextCancellation
// ---------------------------------------------------------------------------

func TestDetectInParameter_ContextCancellation(t *testing.T) {
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount > 1 {
			time.Sleep(200 * time.Millisecond)
		}
		w.WriteHeader(200)
		fmt.Fprint(w, "<result>OK</result>")
	}))
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	opts := DetectOptions{
		MaxPayloads:  50,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	targetURL := ts.URL + "/?xml=test"
	result, err := d.DetectInParameter(ctx, targetURL, "xml", "GET", opts)
	if err == nil {
		if result == nil {
			t.Fatal("expected either an error or a result")
		}
	}
}

// ---------------------------------------------------------------------------
// TestDetectInParameter_MaxPayloadsLimit
// ---------------------------------------------------------------------------

func TestDetectInParameter_MaxPayloadsLimit(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  2,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic, xxe.TypeErrorBased},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	targetURL := ts.URL + "/?xml=test"
	result, err := d.DetectInParameter(context.Background(), targetURL, "xml", "GET", opts)
	if err != nil {
		t.Fatalf("DetectInParameter() error: %v", err)
	}
	if result.TestedPayloads > 2 {
		t.Errorf("TestedPayloads = %d, want <= 2", result.TestedPayloads)
	}
}

// ---------------------------------------------------------------------------
// TestDetectInParameter_ReturnsAfterFirstFinding
// ---------------------------------------------------------------------------

func TestDetectInParameter_ReturnsAfterFirstFinding(t *testing.T) {
	ts := newQueryRoutingMockServer(
		"<result>OK</result>",
		"<result>root:x:0:0:root:/root:/bin/bash</result>",
	)
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  20,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	targetURL := ts.URL + "/?xml=test"
	result, err := d.DetectInParameter(context.Background(), targetURL, "xml", "GET", opts)
	if err != nil {
		t.Fatalf("DetectInParameter() error: %v", err)
	}
	// DetectInParameter returns after the first successful finding.
	if len(result.Findings) != 1 {
		t.Errorf("expected exactly 1 finding, got %d", len(result.Findings))
	}
}

// ---------------------------------------------------------------------------
// TestDetectInParameter_PayloadSendError
// ---------------------------------------------------------------------------

func TestDetectInParameter_PayloadSendError(t *testing.T) {
	// Server accepts baseline, then shuts down before payloads.
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(200)
		fmt.Fprint(w, "<result>OK</result>")
	}))

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  2,
		Timeout:      2 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	targetURL := ts.URL + "/?xml=test"
	// Do baseline first, then close the server.
	// We need to get a valid baseline by making the first request succeed.
	// Then close the server so payload requests fail.
	result, err := d.DetectInParameter(context.Background(), targetURL, "xml", "GET", opts)
	if err != nil {
		t.Logf("got expected error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
	ts.Close()
}

// ---------------------------------------------------------------------------
// TestDetect_PayloadSendErrorContinues
// ---------------------------------------------------------------------------

func TestDetect_PayloadSendErrorContinues(t *testing.T) {
	// Server closes connection after baseline to test the "continue" path
	// in the Detect method when sendXMLPayload returns an error.
	requestCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			w.WriteHeader(200)
			fmt.Fprint(w, "<result>OK</result>")
			return
		}
		// Hijack to simulate connection reset on every subsequent request.
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			if conn != nil {
				conn.Close()
			}
		}
	}))
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  2,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() should not return error when individual payloads fail: %v", err)
	}
	if result.Vulnerable {
		t.Error("expected Vulnerable = false when payloads error out")
	}
	// Even if payloads fail, the counter should still increment.
	if result.TestedPayloads != 2 {
		t.Errorf("TestedPayloads = %d, want 2", result.TestedPayloads)
	}
}

// ---------------------------------------------------------------------------
// TestDetect_DetectedTypeAndTarget
// ---------------------------------------------------------------------------

func TestDetect_DetectedTypeAndTarget(t *testing.T) {
	tests := []struct {
		name       string
		testTypes  []xxe.XXEType
		respBody   string
		wantType   xxe.XXEType
	}{
		{
			name:      "classic type detected",
			testTypes: []xxe.XXEType{xxe.TypeClassic},
			respBody:  "root:x:0:0:root:/root:/bin/bash",
			wantType:  xxe.TypeClassic,
		},
		{
			name:      "error-based type detected",
			testTypes: []xxe.XXEType{xxe.TypeErrorBased},
			respBody:  "Error: failed to load external entity",
			wantType:  xxe.TypeErrorBased,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newRoutingMockServer("<result>OK</result>", tt.respBody)
			defer ts.Close()

			client := internalhttp.NewClient()
			d := New(client)
			opts := DetectOptions{
				MaxPayloads:  5,
				Timeout:      5 * time.Second,
				TestTypes:    tt.testTypes,
				TargetParser: xxe.ParserGeneric,
				ContentType:  "application/xml",
			}

			result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
			if err != nil {
				t.Fatalf("Detect() error: %v", err)
			}
			if !result.Vulnerable {
				t.Fatal("expected Vulnerable = true")
			}
			if result.DetectedType != tt.wantType {
				t.Errorf("DetectedType = %q, want %q", result.DetectedType, tt.wantType)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestDetect_DetectedTarget
// ---------------------------------------------------------------------------

func TestDetect_DetectedTarget(t *testing.T) {
	ts := newRoutingMockServer(
		"<result>OK</result>",
		"<result>root:x:0:0:root:/root:/bin/bash</result>",
	)
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  5,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if !result.Vulnerable {
		t.Fatal("expected Vulnerable = true")
	}
	// First classic payload should target file read.
	if result.DetectedTarget != xxe.TargetFileRead {
		t.Errorf("DetectedTarget = %q, want %q", result.DetectedTarget, xxe.TargetFileRead)
	}
}

// ---------------------------------------------------------------------------
// TestDetect_GenericParserNoFilter
// ---------------------------------------------------------------------------

func TestDetect_GenericParserNoFilter(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  100,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	// With generic parser, all payloads should be used (no filtering).
	allClassic := xxe.GetPayloads(xxe.TypeClassic)
	if result.TestedPayloads != len(allClassic) {
		t.Errorf("TestedPayloads = %d, want %d (all classic payloads)", result.TestedPayloads, len(allClassic))
	}
}

// ---------------------------------------------------------------------------
// TestDetect_DotNetParserFilter
// ---------------------------------------------------------------------------

func TestDetect_DotNetParserFilter(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  100,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserDotNet,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	// .NET parser should filter out non-generic, non-.NET payloads.
	allClassic := xxe.GetPayloads(xxe.TypeClassic)
	var expectedCount int
	for _, p := range allClassic {
		if p.Parser == xxe.ParserGeneric || p.Parser == xxe.ParserDotNet {
			expectedCount++
		}
	}
	if result.TestedPayloads != expectedCount {
		t.Errorf("TestedPayloads = %d, want %d (generic + dotnet only)", result.TestedPayloads, expectedCount)
	}
}

// ---------------------------------------------------------------------------
// TestDetectInParameter_DetectedTypeAndTarget
// ---------------------------------------------------------------------------

func TestDetectInParameter_DetectedTypeAndTarget(t *testing.T) {
	ts := newQueryRoutingMockServer(
		"<result>OK</result>",
		"<result>root:x:0:0:root:/root:/bin/bash</result>",
	)
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  5,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	targetURL := ts.URL + "/?xml=test"
	result, err := d.DetectInParameter(context.Background(), targetURL, "xml", "GET", opts)
	if err != nil {
		t.Fatalf("DetectInParameter() error: %v", err)
	}
	if result.DetectedType != xxe.TypeClassic {
		t.Errorf("DetectedType = %q, want classic", result.DetectedType)
	}
	if result.DetectedTarget != xxe.TargetFileRead {
		t.Errorf("DetectedTarget = %q, want file", result.DetectedTarget)
	}
}

// ---------------------------------------------------------------------------
// TestDetectionResult_InitialState
// ---------------------------------------------------------------------------

func TestDetectionResult_InitialState(t *testing.T) {
	result := &DetectionResult{
		Findings: make([]*core.Finding, 0),
	}

	if result.Vulnerable {
		t.Error("initial Vulnerable should be false")
	}
	if len(result.Findings) != 0 {
		t.Error("initial Findings should be empty")
	}
	if result.TestedPayloads != 0 {
		t.Error("initial TestedPayloads should be 0")
	}
	if result.ExfiltratedData != "" {
		t.Error("initial ExfiltratedData should be empty")
	}
}

// ---------------------------------------------------------------------------
// TestDetect_WindowsVulnerableResponse
// ---------------------------------------------------------------------------

func TestDetect_WindowsVulnerableResponse(t *testing.T) {
	ts := newRoutingMockServer(
		"<result>OK</result>",
		"<result>[fonts]\nCourier=courier.ttf\n[extensions]\n.txt=notepad.exe</result>",
	)
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  5,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("expected Vulnerable = true for Windows content")
	}
}

// ---------------------------------------------------------------------------
// TestDetect_SSRFResponse
// ---------------------------------------------------------------------------

func TestDetect_SSRFResponse(t *testing.T) {
	ts := newRoutingMockServer(
		"<result>OK</result>",
		"<result>ami-0abcdef1234567890\ninstance-id: i-12345</result>",
	)
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  10,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("expected Vulnerable = true for AWS metadata")
	}
}

// ---------------------------------------------------------------------------
// TestDetect_PrivateKeyResponse
// ---------------------------------------------------------------------------

func TestDetect_PrivateKeyResponse(t *testing.T) {
	ts := newRoutingMockServer(
		"<result>OK</result>",
		"-----BEGIN RSA KEY-----\nMIIBogIBAAJBANLJ...\n-----END RSA KEY-----",
	)
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  5,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("expected Vulnerable = true for private key leak")
	}
}

// ---------------------------------------------------------------------------
// TestErrorPatterns
// ---------------------------------------------------------------------------

func TestErrorPatterns(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{name: "external entity error", content: "Error: failed to load external entity", expected: true},
		{name: "error loading external entity", content: "Error loading external entity", expected: true},
		{name: "external entity mention", content: "detected external entity reference", expected: true},
		{name: "SYSTEM entity", content: "SYSTEM entity processing", expected: true},
		{name: "DTD not allowed", content: "DTD not allowed here", expected: true},
		{name: "DOCTYPE disallowed", content: "DOCTYPE disallowed in config", expected: true},
		{name: "entity expansion", content: "entity expansion attack detected", expected: true},
		{name: "recursive entity", content: "recursive entity reference", expected: true},
		{name: "connection refused", content: "Error: connection refused", expected: true},
		{name: "name resolution failed", content: "name resolution failed", expected: true},
		{name: "could not resolve host", content: "could not resolve host evil.com", expected: true},
		{name: "network unreachable", content: "network unreachable", expected: true},
		{name: "permission denied", content: "permission denied on /etc/shadow", expected: true},
		{name: "no such file", content: "no such file or directory", expected: true},
		{name: "failed to open", content: "failed to open the resource", expected: true},
		{name: "file not found", content: "file not found at specified path", expected: true},
		{name: "normal response", content: "<response>OK</response>", expected: false},
		{name: "empty response", content: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasError := false
			for _, pattern := range d.errorPatterns {
				if pattern.MatchString(tt.content) {
					hasError = true
					break
				}
			}
			if hasError != tt.expected {
				t.Errorf("error pattern match = %v, want %v", hasError, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestContentPatterns
// ---------------------------------------------------------------------------

func TestContentPatterns(t *testing.T) {
	client := internalhttp.NewClient()
	d := New(client)

	tests := []struct {
		name     string
		content  string
		expected bool
	}{
		{name: "root:x:0:0:", content: "root:x:0:0:root", expected: true},
		{name: "root with star", content: "root:*:0:0:root", expected: true},
		{name: "daemon line", content: "daemon:x:2:2:daemon:/sbin", expected: true},
		{name: "nobody line", content: "nobody:x:65534:65534:nobody", expected: true},
		{name: "hosts ipv4", content: "127.0.0.1\tlocalhost", expected: true},
		{name: "hosts ipv6", content: "::1\tlocalhost ip6-localhost", expected: true},
		{name: "win fonts", content: "[fonts]\nCourier=courier.ttf", expected: true},
		{name: "win extensions", content: "[extensions]\n.txt=notepad", expected: true},
		{name: "win mci", content: "[mci extensions]\navi=mciavi.drv", expected: true},
		{name: "aws ami", content: "ami-0abcdef1234567890", expected: true},
		{name: "instance-id", content: "instance-id: i-12345", expected: true},
		{name: "PATH env", content: "PATH=/usr/bin:/bin:/sbin", expected: true},
		{name: "HOME env", content: "HOME=/root", expected: true},
		{name: "private key", content: "-----BEGIN RSA KEY-----", expected: true},
		{name: "safe html", content: "<html>Hello World</html>", expected: false},
		{name: "empty", content: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched := false
			for _, pattern := range d.contentPatterns {
				if pattern.MatchString(tt.content) {
					matched = true
					break
				}
			}
			if matched != tt.expected {
				t.Errorf("content pattern match = %v, want %v for %q", matched, tt.expected, tt.content)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestDetect_DoSPayloads
// ---------------------------------------------------------------------------

func TestDetect_DoSPayloads(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  10,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeDoS},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	expectedCount := len(xxe.GetPayloads(xxe.TypeDoS))
	if result.TestedPayloads != expectedCount {
		t.Errorf("TestedPayloads = %d, want %d", result.TestedPayloads, expectedCount)
	}
}

// ---------------------------------------------------------------------------
// TestDetect_BlindPayloads
// ---------------------------------------------------------------------------

func TestDetect_BlindPayloads(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  100,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeBlind},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	expectedCount := len(xxe.GetPayloads(xxe.TypeBlind))
	if result.TestedPayloads != expectedCount {
		t.Errorf("TestedPayloads = %d, want %d", result.TestedPayloads, expectedCount)
	}
}

// ---------------------------------------------------------------------------
// TestDetect_JavaParserFilter
// ---------------------------------------------------------------------------

func TestDetect_JavaParserFilter(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  100,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserJava,
		ContentType:  "application/xml",
	}

	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	allClassic := xxe.GetPayloads(xxe.TypeClassic)
	var expectedCount int
	for _, p := range allClassic {
		if p.Parser == xxe.ParserGeneric || p.Parser == xxe.ParserJava {
			expectedCount++
		}
	}
	if result.TestedPayloads != expectedCount {
		t.Errorf("TestedPayloads = %d, want %d (generic + java)", result.TestedPayloads, expectedCount)
	}
}

// ---------------------------------------------------------------------------
// TestDetect_ContentTypePassedToServer
// ---------------------------------------------------------------------------

func TestDetect_ContentTypePassedToServer(t *testing.T) {
	var receivedContentType string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(200)
		fmt.Fprint(w, "<result>OK</result>")
	}))
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  1,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "text/xml",
	}

	_, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if receivedContentType != "text/xml" {
		t.Errorf("server received Content-Type = %q, want text/xml", receivedContentType)
	}
}

// ---------------------------------------------------------------------------
// TestDetect_MethodPassedToServer
// ---------------------------------------------------------------------------

func TestDetect_MethodPassedToServer(t *testing.T) {
	var receivedMethod string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(200)
		fmt.Fprint(w, "<result>OK</result>")
	}))
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client)
	opts := DetectOptions{
		MaxPayloads:  1,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	_, err := d.Detect(context.Background(), ts.URL, "PUT", opts)
	if err != nil {
		t.Fatalf("Detect() error: %v", err)
	}
	if receivedMethod != "PUT" {
		t.Errorf("server received method = %q, want PUT", receivedMethod)
	}
}

// ---------------------------------------------------------------------------
// TestDetect_VerboseMode
// ---------------------------------------------------------------------------

func TestDetect_VerboseMode(t *testing.T) {
	ts := newMockServer(200, "<result>OK</result>")
	defer ts.Close()

	client := internalhttp.NewClient()
	d := New(client).WithVerbose(true)
	opts := DetectOptions{
		MaxPayloads:  2,
		Timeout:      5 * time.Second,
		TestTypes:    []xxe.XXEType{xxe.TypeClassic},
		TargetParser: xxe.ParserGeneric,
		ContentType:  "application/xml",
	}

	// Verbose mode should not change behavior, just confirm no panics.
	result, err := d.Detect(context.Background(), ts.URL, "POST", opts)
	if err != nil {
		t.Fatalf("Detect() with verbose error: %v", err)
	}
	if result == nil {
		t.Fatal("result should not be nil")
	}
}
