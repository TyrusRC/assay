package xss

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
	xsspayloads "github.com/swiss-knife-for-web-security/skws/internal/payloads/xss"
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

	if detector.contextAnalyzer == nil {
		t.Error("New() did not initialize contextAnalyzer")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client).WithVerbose(true)

	if !detector.verbose {
		t.Error("WithVerbose(true) did not set verbose flag")
	}

	detector2 := New(client).WithVerbose(false)
	if detector2.verbose {
		t.Error("WithVerbose(false) should leave verbose as false")
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
	if !opts.IncludeWAFBypass {
		t.Error("DefaultOptions() IncludeWAFBypass should be true")
	}
	if opts.TestAllContexts {
		t.Error("DefaultOptions() TestAllContexts should be false")
	}
}

func TestDetector_findReflections(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name  string
		body  string
		probe string
		want  int
	}{
		{"single reflection", "Hello probe123 world", "probe123", 1},
		{"multiple reflections", "probe123 and probe123 again", "probe123", 2},
		{"no reflection", "Hello world", "probe123", 0},
		{"at start", "probe123 at start", "probe123", 1},
		{"at end", "at the end probe123", "probe123", 1},
		{"empty body", "", "probe123", 0},
		{"empty probe", "Hello world", "", 0},
		{"three reflections", "aXa bXb cXc", "X", 3},
		{"adjacent reflections", "XXXX", "XX", 2},
		{"probe is entire body", "probe123", "probe123", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reflections := detector.findReflections(tt.body, tt.probe)
			if len(reflections) != tt.want {
				t.Errorf("findReflections() got %d reflections, want %d", len(reflections), tt.want)
			}
		})
	}
}

func TestDetector_analyzeReflectionContext(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		body     string
		position int
		want     xsspayloads.Context
	}{
		{
			name:     "script context",
			body:     `<script>var x = "INJECT";</script>`,
			position: 20,
			want:     xsspayloads.JavaScriptContext,
		},
		{
			name:     "html context",
			body:     `<div>INJECT</div>`,
			position: 5,
			want:     xsspayloads.HTMLContext,
		},
		{
			name:     "attribute context",
			body:     `<input value="INJECT">`,
			position: 14,
			want:     xsspayloads.AttributeContext,
		},
		{
			name:     "style context",
			body:     `<style>body { color: INJECT; }</style>`,
			position: 21,
			want:     xsspayloads.CSSContext,
		},
		{
			name:     "template context jinja2",
			body:     `<div>{{ INJECT }}</div>`,
			position: 9,
			want:     xsspayloads.TemplateContext,
		},
		{
			name:     "template context erb",
			body:     `<div><%= INJECT %></div>`,
			position: 10,
			want:     xsspayloads.TemplateContext,
		},
		{
			name:     "template context freemarker",
			body:     `<div>${INJECT}</div>`,
			position: 7,
			want:     xsspayloads.TemplateContext,
		},
		{
			name:     "template context django",
			body:     `<div>{% INJECT %}</div>`,
			position: 9,
			want:     xsspayloads.TemplateContext,
		},
		{
			name:     "event handler inside attribute",
			body:     `<div onclick="INJECT">`,
			position: 14,
			want:     xsspayloads.JavaScriptContext,
		},
		{
			name:     "url attribute href",
			body:     `<a href="INJECT">`,
			position: 9,
			want:     xsspayloads.URLContext,
		},
		{
			name:     "url attribute src",
			body:     `<img src="INJECT">`,
			position: 10,
			want:     xsspayloads.URLContext,
		},
		{
			name:     "url attribute action",
			body:     `<form action="INJECT">`,
			position: 14,
			want:     xsspayloads.URLContext,
		},
		{
			name:     "position near start of body",
			body:     `<div>INJECT</div>`,
			position: 5,
			want:     xsspayloads.HTMLContext,
		},
		{
			name:     "position at zero",
			body:     `INJECT</div>`,
			position: 0,
			want:     xsspayloads.HTMLContext,
		},
		{
			name:     "position near end of body",
			body:     `<div>some text INJECT`,
			position: 15,
			want:     xsspayloads.HTMLContext,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.analyzeReflectionContext(tt.body, tt.position)
			if got != tt.want {
				t.Errorf("analyzeReflectionContext() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetector_isInsideTag(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name string
		ctx  string
		tag  string
		want bool
	}{
		{"inside script", `<script>var x = 1;</script>`, "script", true},
		{"inside style", `<style>body { }</style>`, "style", true},
		{"not inside script", `<div>text</div>`, "script", false},
		{"opening tag only", `<script>var x = 1;`, "script", true},
		{"closing tag only", `var x = 1;</script>`, "script", false},
		{"no tags", `just plain text`, "script", false},
		{"case insensitive open", `<SCRIPT>var x = 1;</script>`, "script", true},
		{"case insensitive close", `<script>var x = 1;</SCRIPT>`, "script", true},
		{"script with attributes", `<script type="text/javascript">var x;</script>`, "script", true},
		{"open before close", `<script>...</script><script>`, "script", true},
		{"close before open", `</script>text<script>code`, "script", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isInsideTag(tt.ctx, tt.tag)
			if got != tt.want {
				t.Errorf("isInsideTag(%q, %q) = %v, want %v", tt.ctx, tt.tag, got, tt.want)
			}
		})
	}
}

func TestDetector_isInsideAttribute(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name        string
		ctx         string
		relativePos int
		want        bool
	}{
		{"inside double quoted attr", `<input value="INJECT">`, 14, true},
		{"inside single quoted attr", `<input value='INJECT'>`, 14, true},
		{"not in attribute", `<div>INJECT</div>`, 5, false},
		{"after attribute close", `<input value="done">INJECT`, 20, false},
		{"in attr name area", `<input value="test" INJECT>`, 20, false},
		{"equals no quote yet", `<input value=INJECT>`, 14, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isInsideAttribute(tt.ctx, tt.relativePos)
			if got != tt.want {
				t.Errorf("isInsideAttribute() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetector_isEventHandler(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name string
		ctx  string
		want bool
	}{
		{"onclick handler", `<div onclick="alert(1)">`, true},
		{"onmouseover handler", `<div onmouseover="alert(1)">`, true},
		{"onload handler", `<body onload="init()">`, true},
		{"onerror handler", `<img onerror="alert(1)">`, true},
		{"no handler", `<div class="test">`, false},
		{"no handler in text", `some random text`, false},
		{"case insensitive", `<div ONCLICK="alert(1)">`, true},
		{"onfocus handler", `<input onfocus="alert(1)">`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isEventHandler(tt.ctx)
			if got != tt.want {
				t.Errorf("isEventHandler(%q) = %v, want %v", tt.ctx, got, tt.want)
			}
		})
	}
}

func TestDetector_isURLAttribute(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name string
		ctx  string
		want bool
	}{
		{"href attribute", `<a href="http://example.com">`, true},
		{"src attribute", `<img src="image.png">`, true},
		{"action attribute", `<form action="/submit">`, true},
		{"data attribute", `<object data="file.swf">`, true},
		{"poster attribute", `<video poster="thumb.jpg">`, true},
		{"formaction attribute", `<button formaction="/action">`, true},
		{"no url attribute", `<div class="test">`, false},
		{"plain text", `some random text`, false},
		{"case insensitive href", `<a HREF="http://example.com">`, true},
		{"case insensitive src", `<img SRC="image.png">`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isURLAttribute(tt.ctx)
			if got != tt.want {
				t.Errorf("isURLAttribute(%q) = %v, want %v", tt.ctx, got, tt.want)
			}
		})
	}
}

func TestDetector_hasTemplateSyntax(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name    string
		context string
		want    bool
	}{
		{"jinja2 opening", `<div>{{ value }}</div>`, true},
		{"jinja2 closing", `<div>{{ value }}</div>`, true},
		{"erb syntax", `<div><%= value %></div>`, true},
		{"freemarker", `<div>${value}</div>`, true},
		{"django block", `<div>{% block %}</div>`, true},
		{"no template", `<div>plain text</div>`, false},
		{"html only", `<script>alert(1)</script>`, false},
		{"empty string", ``, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.hasTemplateSyntax(tt.context)
			if got != tt.want {
				t.Errorf("hasTemplateSyntax(%q) = %v, want %v", tt.context, got, tt.want)
			}
		})
	}
}

func TestDetector_isPayloadReflected(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name    string
		body    string
		payload xsspayloads.Payload
		want    bool
	}{
		{
			name:    "exact reflection",
			body:    `<img src=x onerror=alert(1)>`,
			payload: xsspayloads.Payload{Value: `<img src=x onerror=alert(1)>`},
			want:    true,
		},
		{
			name:    "no reflection",
			body:    `<div>Safe content</div>`,
			payload: xsspayloads.Payload{Value: `<script>alert(1)</script>`},
			want:    false,
		},
		{
			name:    "partial match with script tag",
			body:    `<script>alert(1)</script>`,
			payload: xsspayloads.Payload{Value: `<script>`},
			want:    true,
		},
		{
			name:    "html encoded reflection with entities",
			body:    `<script>alert(1)</script>`,
			payload: xsspayloads.Payload{Value: `&lt;script&gt;alert(1)&lt;/script&gt;`},
			want:    true,
		},
		{
			name:    "html encoded quote reflection",
			body:    `value="test"`,
			payload: xsspayloads.Payload{Value: `value=&quot;test&quot;`},
			want:    true,
		},
		{
			name:    "no match even with decoding",
			body:    `<div>completely different</div>`,
			payload: xsspayloads.Payload{Value: `&lt;script&gt;alert(1)&lt;/script&gt;`},
			want:    false,
		},
		{
			name:    "payload with amp entity",
			body:    `test&value`,
			payload: xsspayloads.Payload{Value: `test&amp;value`},
			want:    true,
		},
		{
			name:    "payload with single quote entity",
			body:    `it's a test`,
			payload: xsspayloads.Payload{Value: `it&#39;s a test`},
			want:    true,
		},
		{
			name:    "payload same as decoded no change",
			body:    `no entities here`,
			payload: xsspayloads.Payload{Value: `no entities here`},
			want:    true,
		},
		{
			name:    "empty body",
			body:    ``,
			payload: xsspayloads.Payload{Value: `<script>alert(1)</script>`},
			want:    false,
		},
		{
			name:    "empty payload",
			body:    `<div>some content</div>`,
			payload: xsspayloads.Payload{Value: ``},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detector.isPayloadReflected(tt.body, tt.payload)
			if got != tt.want {
				t.Errorf("isPayloadReflected() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetector_htmlDecode(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		input string
		want  string
	}{
		{"&lt;script&gt;", "<script>"},
		{"&quot;test&quot;", `"test"`},
		{"&#39;test&#39;", "'test'"},
		{"&amp;amp;", "&amp;"},
		{"no entities", "no entities"},
		{"", ""},
		{"&lt;&gt;&quot;&#39;&amp;", `<>"'&`},
		{"mixed &lt;content&gt; here", "mixed <content> here"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := detector.htmlDecode(tt.input)
			if got != tt.want {
				t.Errorf("htmlDecode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDetector_deduplicatePayloads(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name     string
		payloads []xsspayloads.Payload
		want     int
	}{
		{
			name: "with duplicates",
			payloads: []xsspayloads.Payload{
				{Value: "payload1"},
				{Value: "payload2"},
				{Value: "payload1"},
				{Value: "payload3"},
				{Value: "payload2"},
			},
			want: 3,
		},
		{
			name: "no duplicates",
			payloads: []xsspayloads.Payload{
				{Value: "a"},
				{Value: "b"},
				{Value: "c"},
			},
			want: 3,
		},
		{
			name:     "empty slice",
			payloads: []xsspayloads.Payload{},
			want:     0,
		},
		{
			name: "all same",
			payloads: []xsspayloads.Payload{
				{Value: "same"},
				{Value: "same"},
				{Value: "same"},
			},
			want: 1,
		},
		{
			name: "single payload",
			payloads: []xsspayloads.Payload{
				{Value: "only"},
			},
			want: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unique := detector.deduplicatePayloads(tt.payloads)
			if len(unique) != tt.want {
				t.Errorf("deduplicatePayloads() returned %d payloads, want %d", len(unique), tt.want)
			}
		})
	}
}

func TestDetector_createFinding(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	tests := []struct {
		name            string
		target          string
		param           string
		payload         xsspayloads.Payload
		resp            *internalhttp.Response
		wantSeverity    core.Severity
		wantType        string
		wantTool        string
		wantHasEvidence bool
	}{
		{
			name:   "reflected XSS finding",
			target: "http://example.com/page",
			param:  "q",
			payload: xsspayloads.Payload{
				Value:       "<script>alert(1)</script>",
				Context:     xsspayloads.HTMLContext,
				Type:        xsspayloads.TypeReflected,
				Description: "Basic script tag",
			},
			resp:            &internalhttp.Response{StatusCode: 200, Body: "reflected"},
			wantSeverity:    core.SeverityHigh,
			wantType:        "Cross-Site Scripting (XSS)",
			wantTool:        "xss-detector",
			wantHasEvidence: true,
		},
		{
			name:   "stored XSS finding critical severity",
			target: "http://example.com/comment",
			param:  "body",
			payload: xsspayloads.Payload{
				Value:       "<script>alert(1)</script>",
				Context:     xsspayloads.HTMLContext,
				Type:        xsspayloads.TypeStored,
				Description: "Stored script tag",
			},
			resp:            &internalhttp.Response{StatusCode: 200, Body: "stored"},
			wantSeverity:    core.SeverityCritical,
			wantType:        "Cross-Site Scripting (XSS)",
			wantTool:        "xss-detector",
			wantHasEvidence: true,
		},
		{
			name:   "DOM XSS finding high severity",
			target: "http://example.com/dom",
			param:  "input",
			payload: xsspayloads.Payload{
				Value:       "alert(1)",
				Context:     xsspayloads.JavaScriptContext,
				Type:        xsspayloads.TypeDOM,
				Description: "eval direct",
			},
			resp:            &internalhttp.Response{StatusCode: 200, Body: "dom xss"},
			wantSeverity:    core.SeverityHigh,
			wantType:        "Cross-Site Scripting (XSS)",
			wantTool:        "xss-detector",
			wantHasEvidence: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := detector.createFinding(tt.target, tt.param, tt.payload, tt.resp)

			if finding == nil {
				t.Fatal("createFinding() returned nil")
			}
			if finding.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", finding.Type, tt.wantType)
			}
			if finding.Severity != tt.wantSeverity {
				t.Errorf("Severity = %v, want %v", finding.Severity, tt.wantSeverity)
			}
			if finding.Tool != tt.wantTool {
				t.Errorf("Tool = %q, want %q", finding.Tool, tt.wantTool)
			}
			if finding.URL != tt.target {
				t.Errorf("URL = %q, want %q", finding.URL, tt.target)
			}
			if finding.Parameter != tt.param {
				t.Errorf("Parameter = %q, want %q", finding.Parameter, tt.param)
			}
			if tt.wantHasEvidence && finding.Evidence == "" {
				t.Error("Expected non-empty Evidence")
			}
			if finding.Remediation == "" {
				t.Error("Expected non-empty Remediation")
			}
			if finding.Description == "" {
				t.Error("Expected non-empty Description")
			}
			if len(finding.WSTG) == 0 {
				t.Error("Expected WSTG mappings")
			}
			if len(finding.Top10) == 0 {
				t.Error("Expected Top10 mappings")
			}
			if len(finding.CWE) == 0 {
				t.Error("Expected CWE mappings")
			}
		})
	}
}

func TestDetector_Detect_VulnerableServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		// Reflect the parameter value directly -- vulnerable to XSS
		fmt.Fprintf(w, "<html><body>Search results for: %s</body></html>", q)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      10,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllContexts:  false,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if !result.Vulnerable {
		t.Error("Expected vulnerability to be detected on a reflecting server")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected at least one finding")
	}

	if result.TestedPayloads == 0 {
		t.Error("Expected some payloads to be tested")
	}
}

func TestDetector_Detect_SafeServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Does not reflect input
		w.Write([]byte("<html><body>Safe response</body></html>"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      5,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}

	if len(result.Findings) != 0 {
		t.Error("Expected no findings for safe server")
	}
}

func TestDetector_Detect_NoReflection(t *testing.T) {
	// Server that does not reflect the probe at all
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>Static content with no reflection</body></html>"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      5,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Should default to HTML context when no reflection found
	if result.DetectedContext != xsspayloads.HTMLContext {
		t.Errorf("Expected HTMLContext when no reflection, got %v", result.DetectedContext)
	}
}

func TestDetector_Detect_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>%s</body></html>", q)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := detector.Detect(ctx, server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads: 100,
		Timeout:     5 * time.Second,
	})

	// Either the probe itself fails or the context error is returned
	if err == nil {
		// If no error, the result should at least exist
		if result == nil {
			t.Fatal("Expected non-nil result even with cancelled context")
		}
	}
}

func TestDetector_Detect_InvalidURL(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), "://invalid-url", "q", "GET", DetectOptions{
		MaxPayloads: 5,
		Timeout:     5 * time.Second,
	})

	if err == nil {
		t.Error("Expected error for invalid URL")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
	}
}

func TestDetector_Detect_TestAllContexts(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		// Reflect input directly
		fmt.Fprintf(w, "<html><body>%s</body></html>", q)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      5,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
		TestAllContexts:  true,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// With TestAllContexts, it should test all contexts and potentially find multiple
	if result.TestedPayloads == 0 {
		t.Error("Expected some payloads to be tested with TestAllContexts")
	}
}

func TestDetector_Detect_WithWAFBypass(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>%s</body></html>", q)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      5,
		IncludeWAFBypass: true,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestDetector_Detect_PayloadLimiting(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("safe"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      3,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// 1 probe + at most MaxPayloads test requests
	// TestedPayloads tracks actual payload tests (not probe)
	if result.TestedPayloads > 3 {
		t.Errorf("Expected at most 3 tested payloads, got %d", result.TestedPayloads)
	}
}

func TestDetector_Detect_HTTPErrorDuringPayloadTest(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount == 1 {
			// First request (probe) succeeds and reflects
			q := r.URL.Query().Get("q")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "<html><body>%s</body></html>", q)
			return
		}
		// Subsequent requests cause server error
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      3,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Should not crash, payload errors are silently continued
	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}

func TestDetector_Detect_ScriptContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		// Reflect inside a script tag
		fmt.Fprintf(w, `<html><script>var search = "%s";</script></html>`, q)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      10,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.DetectedContext != xsspayloads.JavaScriptContext {
		t.Errorf("Expected JavaScriptContext, got %v", result.DetectedContext)
	}
}

func TestDetector_Detect_AttributeContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		// Reflect inside an attribute
		fmt.Fprintf(w, `<html><input value="%s"></html>`, q)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      10,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result.DetectedContext != xsspayloads.AttributeContext {
		t.Errorf("Expected AttributeContext, got %v", result.DetectedContext)
	}
}

func TestDetector_Detect_ServerDown(t *testing.T) {
	// Create a server and immediately close it to simulate connection failure
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverURL := server.URL
	server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), serverURL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads: 5,
		Timeout:     2 * time.Second,
	})

	if err == nil {
		t.Error("Expected error when server is down")
	}

	if result == nil {
		t.Fatal("Expected non-nil result even on error")
	}

	if !strings.Contains(err.Error(), "failed to send probe") {
		t.Errorf("Expected probe error, got: %v", err)
	}
}

func TestDetector_Detect_MaxPayloadsZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html>%s</html>", q)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	// MaxPayloads=0 means no limit
	result, err := detector.Detect(context.Background(), server.URL+"?q=test", "q", "GET", DetectOptions{
		MaxPayloads:      0,
		IncludeWAFBypass: false,
		Timeout:          5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
}
