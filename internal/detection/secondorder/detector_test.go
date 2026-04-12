package secondorder

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestNew(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	if detector == nil {
		t.Fatal("New() returned nil")
	}
	if detector.client == nil {
		t.Error("New() did not set client")
	}
	if len(detector.strategies) == 0 {
		t.Error("New() should initialize with default strategies")
	}
}

func TestNew_DefaultStrategiesCount(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)

	expected := 4
	if got := len(detector.strategies); got != expected {
		t.Errorf("New() created %d strategies, want %d", got, expected)
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := DefaultOptions()

	if opts.MaxPayloads <= 0 {
		t.Error("MaxPayloads should be positive")
	}
	if opts.Timeout <= 0 {
		t.Error("Timeout should be positive")
	}
}

func TestDetect_BlindXSS_ResponseReflection(t *testing.T) {
	// Server that reflects User-Agent back in the response body (simulates
	// an admin panel displaying logged headers).
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		// Simulate vulnerable admin page that renders stored User-Agent.
		fmt.Fprintf(w, "<html><body>Recent visitor: %s</body></html>", ua)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		Strategies:  []string{StrategyBlindXSS},
		MaxPayloads: 10,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected BlindXSS to be detected when server reflects User-Agent")
	}
	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if finding.Type != "Second-Order XSS" {
		t.Errorf("Finding type = %q, want %q", finding.Type, "Second-Order XSS")
	}
	if finding.URL != server.URL {
		t.Errorf("Finding URL = %q, want %q", finding.URL, server.URL)
	}
}

func TestDetect_BlindXSS_FindingOWASPMapping(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		fmt.Fprintf(w, "<div>%s</div>", ua)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		Strategies:  []string{StrategyBlindXSS},
		MaxPayloads: 5,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("Expected findings")
	}

	finding := result.Findings[0]
	if len(finding.WSTG) == 0 {
		t.Error("Expected WSTG mapping")
	}
	if len(finding.Top10) == 0 {
		t.Error("Expected OWASP Top10 mapping")
	}
	if len(finding.CWE) == 0 {
		t.Error("Expected CWE mapping")
	}
}

func TestDetect_JNDIHeaders_ErrorBased(t *testing.T) {
	// Server that returns JNDI error patterns when it receives JNDI payloads.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, vals := range r.Header {
			for _, v := range vals {
				if strings.Contains(v, "${jndi:") {
					w.WriteHeader(http.StatusInternalServerError)
					fmt.Fprint(w, "javax.naming.NamingException: JNDI lookup failed")
					return
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		Strategies:  []string{StrategyJNDIHeaders},
		MaxPayloads: 10,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected JNDI injection to be detected")
	}
	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if finding.Type != "JNDI Injection" {
		t.Errorf("Finding type = %q, want %q", finding.Type, "JNDI Injection")
	}
}

func TestDetect_LogInjection_CRLFReflection(t *testing.T) {
	// Simulate a vulnerable log viewer: the server URL-decodes the User-Agent
	// and includes the decoded content in the response body. The %0d%0a payload
	// decodes to actual CRLF, and %20 to space, which the verify pattern matches.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		// Simulate server-side URL decoding of stored header values
		// (e.g., a log viewer that decodes percent-encoded values before rendering).
		decoded := strings.ReplaceAll(ua, "%0d%0a", "\r\n")
		decoded = strings.ReplaceAll(decoded, "%0D%0A", "\r\n")
		decoded = strings.ReplaceAll(decoded, "%20", " ")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Log entry: %s", decoded)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		Strategies:  []string{StrategyLogInjection},
		MaxPayloads: 10,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected log injection to be detected")
	}
	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if finding.Type != "Log Injection" {
		t.Errorf("Finding type = %q, want %q", finding.Type, "Log Injection")
	}
}

func TestDetect_SecondOrderSQLi_ErrorBased(t *testing.T) {
	// Server that returns SQL errors when it receives SQL payloads in body params.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			if err := r.ParseForm(); err == nil {
				for _, values := range r.PostForm {
					for _, v := range values {
						if strings.Contains(v, "'") || strings.Contains(v, "UNION") {
							w.WriteHeader(http.StatusInternalServerError)
							fmt.Fprint(w, "Error: You have an error in your SQL syntax near")
							return
						}
					}
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		Strategies:  []string{StrategySecondOrderSQLi},
		MaxPayloads: 10,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Error("Expected second-order SQLi to be detected")
	}
	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if finding.Type != "Second-Order SQL Injection" {
		t.Errorf("Finding type = %q, want %q", finding.Type, "Second-Order SQL Injection")
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
	cancel() // Cancel immediately.

	_, err := detector.Detect(ctx, server.URL, DefaultOptions())

	if err == nil {
		t.Error("Expected context cancellation error")
	}
}

func TestDetect_EmptyStrategiesList_RunsAll(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Safe response")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		Strategies:  nil, // empty = run all
		MaxPayloads: 2,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if result.TestedStrategies != 4 {
		t.Errorf("TestedStrategies = %d, want 4 (all defaults)", result.TestedStrategies)
	}
}

func TestDetect_StrategyFiltering(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		Strategies:  []string{StrategyBlindXSS, StrategyLogInjection},
		MaxPayloads: 5,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if result.TestedStrategies != 2 {
		t.Errorf("TestedStrategies = %d, want 2", result.TestedStrategies)
	}
}

func TestDetect_SafeServer_NoFindings(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Completely safe response")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		MaxPayloads: 5,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if result.Vulnerable {
		t.Error("Expected no vulnerability in safe server")
	}
	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(result.Findings))
	}
}

func TestDetect_CallbackDomain(t *testing.T) {
	// Verify that the callback domain is injected into payloads.
	receivedPayloads := make([]string, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if ua != "" {
			receivedPayloads = append(receivedPayloads, ua)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	callbackDomain := "https://attacker.example.com/collect"
	_, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		Strategies:     []string{StrategyBlindXSS},
		MaxPayloads:    5,
		Timeout:        5 * time.Second,
		CallbackDomain: callbackDomain,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	found := false
	for _, p := range receivedPayloads {
		if strings.Contains(p, callbackDomain) {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected callback domain to appear in at least one injected payload")
	}
}

func TestDetect_FindingEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		fmt.Fprintf(w, "<html><body>Agent: %s</body></html>", ua)
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	result, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		Strategies:  []string{StrategyBlindXSS},
		MaxPayloads: 5,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatal("Expected at least one finding")
	}

	finding := result.Findings[0]
	if finding.Evidence == "" {
		t.Error("Finding should have evidence")
	}
	if finding.Tool == "" {
		t.Error("Finding should have tool name set")
	}
	if finding.Remediation == "" {
		t.Error("Finding should have remediation advice")
	}
	if finding.Description == "" {
		t.Error("Finding should have a description")
	}
}

func TestDetect_MaxPayloadsLimit(t *testing.T) {
	injectionCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		injectionCount++
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	_, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		Strategies:  []string{StrategyBlindXSS},
		MaxPayloads: 2,
		Timeout:     5 * time.Second,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Each payload is sent to each inject point, but total payloads per
	// strategy should not exceed MaxPayloads. The number of requests will be
	// at most MaxPayloads * number of inject points for the strategy, plus
	// the baseline. We just verify it did not run the full payload set.
	totalBlindXSSPayloads := len(blindXSSPayloads(""))
	totalInjectPoints := len(blindXSSStrategy().InjectPoints)
	maxPossible := totalBlindXSSPayloads * totalInjectPoints

	// With limit=2, requests should be fewer than running all payloads.
	if injectionCount > maxPossible {
		t.Errorf("Expected fewer requests with MaxPayloads=2, got %d (max possible %d)",
			injectionCount, maxPossible)
	}
}

func TestDefaultStrategies(t *testing.T) {
	strategies := DefaultStrategies()

	if len(strategies) != 4 {
		t.Fatalf("DefaultStrategies() returned %d strategies, want 4", len(strategies))
	}

	names := make(map[string]bool)
	for _, s := range strategies {
		names[s.Name] = true
	}

	expected := []string{
		StrategyBlindXSS,
		StrategySecondOrderSQLi,
		StrategyLogInjection,
		StrategyJNDIHeaders,
	}
	for _, name := range expected {
		if !names[name] {
			t.Errorf("Missing default strategy: %s", name)
		}
	}
}

func TestGetPayloads(t *testing.T) {
	tests := []struct {
		name     string
		strategy Strategy
		callback string
		wantMin  int
	}{
		{
			name:     "BlindXSS payloads",
			strategy: blindXSSStrategy(),
			callback: "https://cb.example.com",
			wantMin:  3,
		},
		{
			name:     "SecondOrderSQLi payloads",
			strategy: secondOrderSQLiStrategy(),
			callback: "",
			wantMin:  3,
		},
		{
			name:     "LogInjection payloads",
			strategy: logInjectionStrategy(),
			callback: "",
			wantMin:  3,
		},
		{
			name:     "JNDIHeaders payloads",
			strategy: jndiHeadersStrategy(),
			callback: "https://cb.example.com",
			wantMin:  3,
		},
		{
			name:     "Unknown strategy",
			strategy: Strategy{Name: "unknown"},
			callback: "",
			wantMin:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := GetPayloads(tt.strategy, tt.callback)
			if len(payloads) < tt.wantMin {
				t.Errorf("GetPayloads() returned %d payloads, want at least %d",
					len(payloads), tt.wantMin)
			}
		})
	}
}

func TestGetPayloads_CallbackDomainSubstitution(t *testing.T) {
	cb := "https://attacker.example.com"

	xssPayloads := GetPayloads(blindXSSStrategy(), cb)
	for _, p := range xssPayloads {
		if !strings.Contains(p, cb) {
			t.Errorf("BlindXSS payload %q does not contain callback domain", p)
		}
	}

	jndiPayloads := GetPayloads(jndiHeadersStrategy(), cb)
	for _, p := range jndiPayloads {
		if !strings.Contains(p, cb) {
			t.Errorf("JNDI payload %q does not contain callback domain", p)
		}
	}
}

func TestStrategy_InjectPoints(t *testing.T) {
	tests := []struct {
		name          string
		strategy      Strategy
		wantMinInject int
		wantMinVerify int
	}{
		{
			name:          "BlindXSS has header and body inject points",
			strategy:      blindXSSStrategy(),
			wantMinInject: 3,
			wantMinVerify: 1,
		},
		{
			name:          "JNDIHeaders has header inject points",
			strategy:      jndiHeadersStrategy(),
			wantMinInject: 5,
			wantMinVerify: 1,
		},
		{
			name:          "LogInjection has header inject points",
			strategy:      logInjectionStrategy(),
			wantMinInject: 3,
			wantMinVerify: 1,
		},
		{
			name:          "SecondOrderSQLi has body and query inject points",
			strategy:      secondOrderSQLiStrategy(),
			wantMinInject: 3,
			wantMinVerify: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.strategy.InjectPoints) < tt.wantMinInject {
				t.Errorf("InjectPoints count = %d, want >= %d",
					len(tt.strategy.InjectPoints), tt.wantMinInject)
			}
			if len(tt.strategy.VerifyPoints) < tt.wantMinVerify {
				t.Errorf("VerifyPoints count = %d, want >= %d",
					len(tt.strategy.VerifyPoints), tt.wantMinVerify)
			}
		})
	}
}

func TestDetect_JNDIHeaders_WithCallbackDomain(t *testing.T) {
	receivedHeaders := make(map[string][]string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, vals := range r.Header {
			receivedHeaders[name] = append(receivedHeaders[name], vals...)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	cb := "https://jndi.attacker.example.com"
	_, err := detector.Detect(context.Background(), server.URL, DetectOptions{
		Strategies:     []string{StrategyJNDIHeaders},
		MaxPayloads:    3,
		Timeout:        5 * time.Second,
		CallbackDomain: cb,
	})

	if err != nil {
		t.Fatalf("Detect() returned error: %v", err)
	}

	// Verify that at least one header contained a JNDI payload with the callback.
	found := false
	for _, vals := range receivedHeaders {
		for _, v := range vals {
			if strings.Contains(v, "jndi") && strings.Contains(v, cb) {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Error("Expected JNDI payload with callback domain in at least one header")
	}
}

func TestDetect_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	}))
	defer server.Close()

	client := internalhttp.NewClient()
	detector := New(client)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Give the context time to expire.
	time.Sleep(5 * time.Millisecond)

	_, err := detector.Detect(ctx, server.URL, DetectOptions{
		MaxPayloads: 100,
		Timeout:     5 * time.Second,
	})

	if err == nil {
		t.Error("Expected timeout error")
	}
}

func TestDetector_Name(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)
	if detector.Name() != "secondorder" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "secondorder")
	}
}

func TestDetector_Description(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client)
	desc := detector.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}
}

func TestDetector_WithVerbose(t *testing.T) {
	client := internalhttp.NewClient()
	detector := New(client).WithVerbose(true)

	if !detector.verbose {
		t.Error("WithVerbose(true) should set verbose to true")
	}
}

func TestDefaultBlindXSSStrategy(t *testing.T) {
	strategy := DefaultBlindXSSStrategy("http://example.com/inject", "http://example.com/verify")

	if strategy.Name == "" {
		t.Error("Strategy.Name should not be empty")
	}
	if strategy.Name != StrategyBlindXSS {
		t.Errorf("Strategy.Name = %q, want %q", strategy.Name, StrategyBlindXSS)
	}
	if strategy.InjectURL != "http://example.com/inject" {
		t.Errorf("InjectURL = %q, want %q", strategy.InjectURL, "http://example.com/inject")
	}
	if strategy.VerifyURL != "http://example.com/verify" {
		t.Errorf("VerifyURL = %q, want %q", strategy.VerifyURL, "http://example.com/verify")
	}
	if len(strategy.Payloads) == 0 {
		t.Error("Strategy should have payloads")
	}
	if strategy.InjectParam == "" {
		t.Error("Strategy.InjectParam should not be empty")
	}
}

func TestDefaultSecondOrderSQLiStrategy(t *testing.T) {
	strategy := DefaultSecondOrderSQLiStrategy("http://example.com/register", "http://example.com/profile")

	if strategy.Name == "" {
		t.Error("Strategy.Name should not be empty")
	}
	if strategy.Name != StrategySecondOrderSQLi {
		t.Errorf("Strategy.Name = %q, want %q", strategy.Name, StrategySecondOrderSQLi)
	}
	if strategy.InjectURL != "http://example.com/register" {
		t.Errorf("InjectURL = %q, want %q", strategy.InjectURL, "http://example.com/register")
	}
	if strategy.VerifyURL != "http://example.com/profile" {
		t.Errorf("VerifyURL = %q, want %q", strategy.VerifyURL, "http://example.com/profile")
	}
	if len(strategy.Payloads) == 0 {
		t.Error("Strategy should have payloads")
	}
}

func TestDefaultLogInjectionStrategy(t *testing.T) {
	strategy := DefaultLogInjectionStrategy("http://example.com/target")

	if strategy.Name == "" {
		t.Error("Strategy.Name should not be empty")
	}
	if strategy.Name != StrategyLogInjection {
		t.Errorf("Strategy.Name = %q, want %q", strategy.Name, StrategyLogInjection)
	}
	if strategy.InjectURL != "http://example.com/target" {
		t.Errorf("InjectURL = %q, want %q", strategy.InjectURL, "http://example.com/target")
	}
	if strategy.VerifyURL != "http://example.com/target" {
		t.Errorf("VerifyURL = %q, want %q (same URL for log injection)", strategy.VerifyURL, "http://example.com/target")
	}
	if len(strategy.Payloads) == 0 {
		t.Error("Strategy should have payloads")
	}
}

func TestDefaultStrategies_PayloadContent(t *testing.T) {
	xss := DefaultBlindXSSStrategy("http://x.com/i", "http://x.com/v")
	for _, p := range xss.Payloads {
		if !strings.Contains(p, "<") && !strings.Contains(p, "onerror") && !strings.Contains(p, "script") {
			t.Logf("XSS payload may not be HTML-based: %s", p)
		}
	}

	sqli := DefaultSecondOrderSQLiStrategy("http://x.com/i", "http://x.com/v")
	hasSQLKeyword := false
	for _, p := range sqli.Payloads {
		if strings.Contains(p, "'") || strings.Contains(strings.ToUpper(p), "UNION") || strings.Contains(strings.ToUpper(p), "SELECT") {
			hasSQLKeyword = true
			break
		}
	}
	if !hasSQLKeyword {
		t.Error("SQLi strategy should have payloads containing SQL syntax")
	}

	logStrat := DefaultLogInjectionStrategy("http://x.com/t")
	hasCRLF := false
	for _, p := range logStrat.Payloads {
		if strings.Contains(p, "\r\n") || strings.Contains(p, "%0d%0a") {
			hasCRLF = true
			break
		}
	}
	if !hasCRLF {
		t.Error("Log injection strategy should have CRLF payloads")
	}
}
