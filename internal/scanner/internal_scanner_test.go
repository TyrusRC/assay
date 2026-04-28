package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/techstack"
)

// TestInternalScanner_OOBReady_ConcurrentAccess exercises the internal
// bookkeeping for s.oobReady. Readers (waitForOOBClient) must not race
// with writers (startOOBClientAsync). Most effective under `go test -race`.
func TestInternalScanner_OOBReady_ConcurrentAccess(t *testing.T) {
	s := &InternalScanner{
		config: &InternalScanConfig{EnableOOB: true},
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			// Simulates what startOOBClientAsync does: set up oobReady
			// under the mutex. (We skip the real oob.NewClient to keep
			// the test hermetic — no network.)
			s.mu.Lock()
			if s.oobReady == nil {
				ch := make(chan struct{})
				close(ch)
				s.oobReady = ch
			}
			s.mu.Unlock()
		}()
		go func() {
			defer wg.Done()
			_ = s.waitForOOBClient(10 * time.Millisecond)
		}()
	}
	wg.Wait()
}

// TestInternalScanner_TechHint_ConcurrentWrites verifies that concurrent
// writes to s.techHint are serialized under s.mu. Meaningful under -race.
func TestInternalScanner_TechHint_ConcurrentWrites(t *testing.T) {
	s := &InternalScanner{
		config: &InternalScanConfig{},
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hint := &TechHint{Technologies: []string{"php"}}
			s.mu.Lock()
			s.techHint = hint
			s.mu.Unlock()
		}()
	}
	wg.Wait()

	s.mu.Lock()
	got := s.techHint
	s.mu.Unlock()
	if got == nil {
		t.Error("techHint should be set after concurrent writes")
	}
}

func TestNewInternalScanner(t *testing.T) {
	scanner, err := NewInternalScanner(nil)

	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}
	if scanner == nil {
		t.Fatal("NewInternalScanner() returned nil")
	}
	if scanner.client == nil {
		t.Error("scanner.client is nil")
	}
	if scanner.sqliDetector == nil {
		t.Error("scanner.sqliDetector is nil")
	}
	if scanner.xssDetector == nil {
		t.Error("scanner.xssDetector is nil")
	}
}

func TestNewInternalScanner_WithConfig(t *testing.T) {
	config := &InternalScanConfig{
		EnableSQLi:          true,
		EnableXSS:           false,
		MaxPayloadsPerParam: 10,
		RequestTimeout:      5 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}
	if scanner.config.EnableXSS != false {
		t.Error("Config EnableXSS should be false")
	}
	if scanner.config.MaxPayloadsPerParam != 10 {
		t.Errorf("Config MaxPayloadsPerParam = %d, want 10", scanner.config.MaxPayloadsPerParam)
	}
}

func TestDefaultInternalConfig(t *testing.T) {
	config := DefaultInternalConfig()

	// Parameter-level detectors enabled by default
	if !config.EnableSQLi {
		t.Error("Default EnableSQLi should be true")
	}
	if !config.EnableXSS {
		t.Error("Default EnableXSS should be true")
	}
	if !config.EnableCMDI {
		t.Error("Default EnableCMDI should be true")
	}
	if !config.EnableSSRF {
		t.Error("Default EnableSSRF should be true")
	}
	if !config.EnableLFI {
		t.Error("Default EnableLFI should be true")
	}
	if !config.EnableXXE {
		t.Error("Default EnableXXE should be true")
	}
	if !config.EnableNoSQL {
		t.Error("Default EnableNoSQL should be true")
	}
	if !config.EnableSSTI {
		t.Error("Default EnableSSTI should be true")
	}
	if !config.EnableRedirect {
		t.Error("Default EnableRedirect should be true")
	}
	if !config.EnableCRLF {
		t.Error("Default EnableCRLF should be true")
	}
	if !config.EnableLDAP {
		t.Error("Default EnableLDAP should be true")
	}
	if !config.EnableXPath {
		t.Error("Default EnableXPath should be true")
	}
	if !config.EnableHeaderInj {
		t.Error("Default EnableHeaderInj should be true")
	}
	if !config.EnableCSTI {
		t.Error("Default EnableCSTI should be true")
	}
	if !config.EnableRFI {
		t.Error("Default EnableRFI should be true")
	}

	// URL-level detectors
	if !config.EnableIDOR {
		t.Error("Default EnableIDOR should be true")
	}
	if !config.EnableCORS {
		t.Error("Default EnableCORS should be true")
	}
	if !config.EnableJNDI {
		t.Error("Default EnableJNDI should be true")
	}
	if !config.EnableSecHeaders {
		t.Error("Default EnableSecHeaders should be true")
	}
	if !config.EnableExposure {
		t.Error("Default EnableExposure should be true")
	}
	if !config.EnableCloud {
		t.Error("Default EnableCloud should be true")
	}
	if !config.EnableTLS {
		t.Error("Default EnableTLS should be true")
	}
	if !config.EnableGraphQL {
		t.Error("Default EnableGraphQL should be true")
	}
	if !config.EnableSmuggling {
		t.Error("Default EnableSmuggling should be true")
	}
	if !config.EnableBehavior {
		t.Error("Default EnableBehavior should be true")
	}

	// Discovery enabled by default
	if !config.EnableDiscovery {
		t.Error("Default EnableDiscovery should be true")
	}

	// Storage injection disabled by default (requires Chrome)
	if config.EnableStorageInj {
		t.Error("Default EnableStorageInj should be false")
	}

	// Disabled by default (requires extra config)
	if config.EnableJWT {
		t.Error("Default EnableJWT should be false")
	}
	if config.EnableSubTakeover {
		t.Error("Default EnableSubTakeover should be false")
	}
	if config.EnableAuth {
		t.Error("Default EnableAuth should be false")
	}

	// Scan intensity defaults
	if config.MaxPayloadsPerParam <= 0 {
		t.Error("Default MaxPayloadsPerParam should be positive")
	}
	if config.RequestTimeout <= 0 {
		t.Error("Default RequestTimeout should be positive")
	}
}

func TestInternalScanner_NewDetectorsInitialized(t *testing.T) {
	scanner, err := NewInternalScanner(nil)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	// Parameter-level detectors
	detectors := map[string]interface{}{
		"nosqlDetector":       scanner.nosqlDetector,
		"sstiDetector":        scanner.sstiDetector,
		"idorDetector":        scanner.idorDetector,
		"jwtDetector":         scanner.jwtDetector,
		"redirectDetector":    scanner.redirectDetector,
		"corsDetector":        scanner.corsDetector,
		"crlfDetector":        scanner.crlfDetector,
		"ldapDetector":        scanner.ldapDetector,
		"xpathDetector":       scanner.xpathDetector,
		"headerInjDetector":   scanner.headerInjDetector,
		"cstiDetector":        scanner.cstiDetector,
		"rfiDetector":         scanner.rfiDetector,
		"jndiDetector":        scanner.jndiDetector,
		"secHeadersDetector":  scanner.secHeadersDetector,
		"exposureDetector":    scanner.exposureDetector,
		"cloudDetector":       scanner.cloudDetector,
		"subTakeoverDetector": scanner.subTakeoverDetector,
		"tlsAnalyzer":         scanner.tlsAnalyzer,
		"authDetector":        scanner.authDetector,
		"graphqlDetector":     scanner.graphqlDetector,
		"smugglingDetector":   scanner.smugglingDetector,
		"behaviorDetector":    scanner.behaviorDetector,
	}

	for name, d := range detectors {
		if d == nil {
			t.Errorf("%s should be initialized", name)
		}
	}
}

func TestInternalScanner_ExtractParameters(t *testing.T) {
	scanner, _ := NewInternalScanner(nil)

	tests := []struct {
		name           string
		url            string
		headers        map[string]string
		expectedParams []core.Parameter
	}{
		{
			name: "single query parameter",
			url:  "https://example.com/page?id=1",
			expectedParams: []core.Parameter{
				{Name: "id", Location: core.ParamLocationQuery, Value: "1", Type: "string"},
			},
		},
		{
			name: "multiple query parameters",
			url:  "https://example.com/search?q=test&page=1&sort=asc",
			expectedParams: []core.Parameter{
				{Name: "q", Location: core.ParamLocationQuery, Value: "test", Type: "string"},
				{Name: "page", Location: core.ParamLocationQuery, Value: "1", Type: "string"},
				{Name: "sort", Location: core.ParamLocationQuery, Value: "asc", Type: "string"},
			},
		},
		{
			name:           "no parameters at all",
			url:            "https://example.com/page",
			expectedParams: []core.Parameter{},
		},
		{
			name: "numeric path segments as parameters",
			url:  "https://example.com/users/12345/profile",
			expectedParams: []core.Parameter{
				{Name: "path_1", Location: core.ParamLocationPath, Value: "12345", Type: "number"},
			},
		},
		{
			name: "UUID path segment as parameter",
			url:  "https://example.com/items/550e8400-e29b-41d4-a716-446655440000/detail",
			expectedParams: []core.Parameter{
				{Name: "path_1", Location: core.ParamLocationPath, Value: "550e8400-e29b-41d4-a716-446655440000", Type: "string"},
			},
		},
		{
			name: "combined query and path parameters",
			url:  "https://example.com/users/42/profile?tab=settings",
			expectedParams: []core.Parameter{
				{Name: "tab", Location: core.ParamLocationQuery, Value: "settings", Type: "string"},
				{Name: "path_1", Location: core.ParamLocationPath, Value: "42", Type: "number"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target, err := core.NewTarget(tt.url)
			if err != nil {
				t.Fatalf("NewTarget() error = %v", err)
			}

			params := scanner.extractParameters(target)

			if len(params) != len(tt.expectedParams) {
				t.Errorf("extractParameters() count = %d, want %d; got %v", len(params), len(tt.expectedParams), params)
				return
			}

			for _, expected := range tt.expectedParams {
				found := false
				for _, param := range params {
					if param.Name == expected.Name && param.Location == expected.Location {
						found = true
						if param.Value != expected.Value {
							t.Errorf("param %q value = %q, want %q", expected.Name, param.Value, expected.Value)
						}
						if param.Type != expected.Type {
							t.Errorf("param %q type = %q, want %q", expected.Name, param.Type, expected.Type)
						}
						break
					}
				}
				if !found {
					t.Errorf("extractParameters() missing expected param: Name=%q Location=%q", expected.Name, expected.Location)
				}
			}
		})
	}
}

func TestInternalScanner_ExtractParameters_Cookies(t *testing.T) {
	config := DefaultInternalConfig()
	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	target, err := core.NewTarget("https://example.com/page")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	// The scanner uses a Config from the Scan call which has Cookies.
	// extractParameters should also accept cookies to parse.
	params := scanner.extractParametersWithConfig(target, &Config{
		Cookies: "session=abc123; user_id=42",
	})

	// Should have cookie parameters extracted
	foundSession := false
	foundUserID := false
	for _, p := range params {
		if p.Name == "session" && p.Location == core.ParamLocationCookie {
			foundSession = true
			if p.Value != "abc123" {
				t.Errorf("cookie session value = %q, want %q", p.Value, "abc123")
			}
		}
		if p.Name == "user_id" && p.Location == core.ParamLocationCookie {
			foundUserID = true
			if p.Value != "42" {
				t.Errorf("cookie user_id value = %q, want %q", p.Value, "42")
			}
		}
	}
	if !foundSession {
		t.Error("extractParametersWithConfig() missing cookie param: session")
	}
	if !foundUserID {
		t.Error("extractParametersWithConfig() missing cookie param: user_id")
	}
}

func TestInternalScanner_ExtractParameters_InvalidURL(t *testing.T) {
	scanner, _ := NewInternalScanner(nil)

	// Use a target with a valid scheme but test that malformed path handling works
	target, err := core.NewTarget("https://example.com")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	params := scanner.extractParameters(target)
	// No query params, no path segments that look like IDs
	if len(params) != 0 {
		t.Errorf("extractParameters() for bare URL should return empty, got %v", params)
	}
}

func TestInternalScanner_ExtractParameters_PathSegments_NonID(t *testing.T) {
	scanner, _ := NewInternalScanner(nil)

	// Path segments that are NOT IDs should NOT be extracted
	target, err := core.NewTarget("https://example.com/users/profile/settings")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	params := scanner.extractParameters(target)
	for _, p := range params {
		if p.Location == core.ParamLocationPath {
			t.Errorf("non-ID path segment %q should not be extracted as parameter", p.Value)
		}
	}
}

// TestInternalScanner_Scan_NoParameters confirms that a target with zero
// discoverable parameters still produces a usable scan result. URL-level
// detectors (secheaders, TLS, smuggling, WS, etc.) audit the host, not
// individual parameters, and must run regardless. The previous behavior
// was a hard early-return that incorrectly skipped them.
func TestInternalScanner_Scan_NoParameters(t *testing.T) {
	config := &InternalScanConfig{
		EnableSQLi:     true,
		EnableXSS:      true,
		EnableIDOR:     false,
		EnableCORS:     false,
		RequestTimeout: 5 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	target, err := core.NewTarget("https://example.com/page")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	ctx := context.Background()
	result, err := scanner.Scan(ctx, target, nil)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
	}
	if result == nil {
		t.Fatal("Scan() returned nil result")
	}
}

func TestInternalScanner_Scan_ContextCancellation(t *testing.T) {
	config := &InternalScanConfig{
		EnableSQLi:     true,
		RequestTimeout: 5 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	target, err := core.NewTarget("https://example.com/page?id=1")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = scanner.Scan(ctx, target, nil)

	if err != nil && err != context.Canceled {
		t.Logf("Scan() completed with error: %v (this is acceptable)", err)
	}
}

func TestInternalScanner_Close(t *testing.T) {
	scanner, err := NewInternalScanner(nil)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	scanner.Close()
}

func TestInternalScanner_Scan_AllDetectorsEnabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableSQLi:          true,
		EnableXSS:           true,
		EnableCMDI:          true,
		EnableSSRF:          true,
		EnableLFI:           true,
		EnableXXE:           true,
		EnableNoSQL:         true,
		EnableSSTI:          true,
		EnableIDOR:          true,
		EnableRedirect:      true,
		EnableCORS:          true,
		EnableCRLF:          true,
		EnableLDAP:          true,
		EnableXPath:         true,
		EnableHeaderInj:     true,
		EnableCSTI:          true,
		EnableRFI:           true,
		EnableJNDI:          true,
		EnableSecHeaders:    true,
		EnableExposure:      true,
		EnableCloud:         true,
		EnableTLS:           true,
		EnableGraphQL:       true,
		EnableSmuggling:     true,
		EnableBehavior:      true,
		EnableOOB:           false,
		EnableJWT:           false,
		EnableSubTakeover:   false,
		EnableAuth:          false,
		MaxPayloadsPerParam: 5,
		RequestTimeout:      5 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}
	defer scanner.Close()

	target, err := core.NewTarget(server.URL + "?id=1&name=test")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, target, nil)

	if err != nil {
		t.Errorf("Scan() error = %v", err)
	}
	if result == nil {
		t.Fatal("Scan() returned nil result")
	}

	t.Logf("Scan completed: %d findings, %d errors", len(result.Findings), len(result.Errors))
}

func TestInternalScanner_DiscoveryEnabled(t *testing.T) {
	config := DefaultInternalConfig()
	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}
	defer scanner.Close()

	if scanner.discoveryPipeline == nil {
		t.Error("discoveryPipeline should be initialized when EnableDiscovery is true")
	}
	if len(scanner.discoveryPipeline.Discoverers()) == 0 {
		t.Error("discoveryPipeline should have registered discoverers")
	}
}

func TestInternalScanner_DiscoveryDisabled(t *testing.T) {
	config := DefaultInternalConfig()
	config.EnableDiscovery = false
	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}
	defer scanner.Close()

	if scanner.discoveryPipeline != nil {
		t.Error("discoveryPipeline should be nil when EnableDiscovery is false")
	}
}

func TestInternalScanner_StorageInjDisabledByDefault(t *testing.T) {
	config := DefaultInternalConfig()
	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}
	defer scanner.Close()

	if scanner.headlessPool != nil {
		t.Error("headlessPool should be nil when EnableStorageInj is false")
	}
	if scanner.storageInjDetector != nil {
		t.Error("storageInjDetector should be nil when EnableStorageInj is false")
	}
}

func TestInternalScanner_Scan_WithDiscovery(t *testing.T) {
	// Server responds with an HTML form, so discovery should find form params
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Set-Cookie", "session=abc123; Path=/")
		w.Write([]byte(`<html><body>
			<form method="POST" action="/submit">
				<input type="text" name="username">
				<input type="password" name="password">
			</form>
		</body></html>`))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableDiscovery:     true,
		EnableSQLi:          true,
		EnableXSS:           false,
		EnableOOB:           false,
		EnableIDOR:          false,
		EnableCORS:          false,
		MaxPayloadsPerParam: 3,
		RequestTimeout:      5 * time.Second,
	}

	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}
	defer scanner.Close()

	// Use URL without query params - discovery should still find form params
	target, err := core.NewTarget(server.URL + "/page")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := scanner.Scan(ctx, target, nil)
	if err != nil {
		t.Errorf("Scan() error = %v", err)
	}
	if result == nil {
		t.Fatal("Scan() returned nil result")
	}

	// Discovery should have found params, so we should NOT get "no parameters" error
	for _, e := range result.Errors {
		if strings.Contains(e, "no parameters") {
			t.Error("Discovery should have found form parameters, but got 'no parameters' error")
		}
	}
}

func TestInternalScanner_ApplicableTests_QueryParam(t *testing.T) {
	scanner, _ := NewInternalScanner(nil)
	param := core.Parameter{Name: "id", Location: core.ParamLocationQuery}
	tests := scanner.applicableTests(param)

	// Query params should get ALL injection detectors
	expectedNames := []string{"sqli", "xss", "cmdi", "ssrf", "lfi", "xxe", "nosql", "ssti", "redirect", "crlf", "ldap", "xpath", "headerinj", "csti", "rfi", "csvinj"}
	if len(tests) != len(expectedNames) {
		t.Errorf("applicableTests(query) returned %d tests, want %d", len(tests), len(expectedNames))
	}
	for _, name := range expectedNames {
		found := false
		for _, test := range tests {
			if test.name == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("applicableTests(query) missing test %q", name)
		}
	}
}

func TestInternalScanner_ApplicableTests_CookieParam(t *testing.T) {
	scanner, _ := NewInternalScanner(nil)
	param := core.Parameter{Name: "session", Location: core.ParamLocationCookie}
	tests := scanner.applicableTests(param)

	// Cookie params should get a subset
	allowedNames := map[string]bool{"sqli": true, "xss": true, "crlf": true, "headerinj": true, "nosql": true}
	for _, test := range tests {
		if !allowedNames[test.name] {
			t.Errorf("applicableTests(cookie) should not include %q", test.name)
		}
	}
	if len(tests) == 0 {
		t.Error("applicableTests(cookie) returned no tests")
	}
}

func TestInternalScanner_ApplicableTests_HeaderParam(t *testing.T) {
	scanner, _ := NewInternalScanner(nil)
	param := core.Parameter{Name: "X-Forwarded-For", Location: core.ParamLocationHeader}
	tests := scanner.applicableTests(param)

	// Header params should get crlf, headerinj, ssti, ssrf
	allowedNames := map[string]bool{"crlf": true, "headerinj": true, "ssti": true, "ssrf": true}
	for _, test := range tests {
		if !allowedNames[test.name] {
			t.Errorf("applicableTests(header) should not include %q", test.name)
		}
	}
	if len(tests) == 0 {
		t.Error("applicableTests(header) returned no tests")
	}
}

func TestInternalScanner_ApplicableTests_PathParam(t *testing.T) {
	scanner, _ := NewInternalScanner(nil)
	param := core.Parameter{Name: "path_1", Location: core.ParamLocationPath}
	tests := scanner.applicableTests(param)

	// Path params should get sqli, lfi, cmdi
	allowedNames := map[string]bool{"sqli": true, "lfi": true, "cmdi": true, "nosql": true, "xpath": true}
	for _, test := range tests {
		if !allowedNames[test.name] {
			t.Errorf("applicableTests(path) should not include %q", test.name)
		}
	}
	if len(tests) == 0 {
		t.Error("applicableTests(path) returned no tests")
	}
}

func TestInternalScanner_ApplicableTests_StorageParam(t *testing.T) {
	scanner, _ := NewInternalScanner(nil)
	param := core.Parameter{Name: "token", Location: core.ParamLocationLocalStorage}
	tests := scanner.applicableTests(param)

	// localStorage params should get xss only
	allowedNames := map[string]bool{"xss": true}
	for _, test := range tests {
		if !allowedNames[test.name] {
			t.Errorf("applicableTests(localstorage) should not include %q", test.name)
		}
	}
}

func TestInternalScanner_TechAwareConfig(t *testing.T) {
	scanner, err := NewInternalScanner(nil)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	tests := []struct {
		name       string
		techResult *techstack.DetectionResult
		wantTechs  []string
	}{
		{
			name: "PHP detected",
			techResult: &techstack.DetectionResult{
				URL: "https://example.com",
				Technologies: []techstack.Technology{
					{Name: "PHP", Version: "8.1"},
				},
			},
			wantTechs: []string{"php"},
		},
		{
			name: "Java detected",
			techResult: &techstack.DetectionResult{
				URL: "https://example.com",
				Technologies: []techstack.Technology{
					{Name: "Java"},
				},
			},
			wantTechs: []string{"java"},
		},
		{
			name: "multiple technologies detected",
			techResult: &techstack.DetectionResult{
				URL: "https://example.com",
				Technologies: []techstack.Technology{
					{Name: "PHP", Version: "8.1"},
					{Name: "Apache", Version: "2.4"},
					{Name: "WordPress"},
				},
			},
			wantTechs: []string{"php", "apache", "wordpress"},
		},
		{
			name: "no technologies",
			techResult: &techstack.DetectionResult{
				URL:          "https://example.com",
				Technologies: []techstack.Technology{},
			},
			wantTechs: []string{},
		},
		{
			name:       "nil techResult",
			techResult: nil,
			wantTechs:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint := scanner.techAwareConfig(tt.techResult)
			if hint == nil {
				t.Fatal("techAwareConfig() returned nil")
			}

			if len(hint.Technologies) != len(tt.wantTechs) {
				t.Fatalf("techAwareConfig() Technologies count = %d, want %d; got %v",
					len(hint.Technologies), len(tt.wantTechs), hint.Technologies)
			}

			for _, want := range tt.wantTechs {
				found := false
				for _, got := range hint.Technologies {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("techAwareConfig() missing expected tech %q in %v", want, hint.Technologies)
				}
			}
		})
	}
}

func TestInternalScanner_TechAwareConfig_NormalizesCase(t *testing.T) {
	scanner, err := NewInternalScanner(nil)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	techResult := &techstack.DetectionResult{
		URL: "https://example.com",
		Technologies: []techstack.Technology{
			{Name: "Spring Boot"},
			{Name: "NGINX"},
			{Name: "jQuery"},
		},
	}

	hint := scanner.techAwareConfig(techResult)
	if hint == nil {
		t.Fatal("techAwareConfig() returned nil")
	}

	for _, tech := range hint.Technologies {
		if tech != strings.ToLower(tech) {
			t.Errorf("techAwareConfig() technology %q is not lowercase", tech)
		}
	}
}

func TestShouldSkipDetector_SQLiConfirmed(t *testing.T) {
	cf := newConfirmedFindings()

	// Before any findings, nothing should be skipped
	if cf.shouldSkip("id", "nosql") {
		t.Error("shouldSkip should return false before any findings")
	}

	// Confirm SQLi on "id" parameter
	cf.confirm("id", "sqli")

	// NoSQL, XPath, LDAP should be skipped after SQLi confirmed
	skippedAfterSQLi := []string{"nosql", "xpath", "ldap"}
	for _, detector := range skippedAfterSQLi {
		if !cf.shouldSkip("id", detector) {
			t.Errorf("shouldSkip(%q, %q) should be true after SQLi confirmed", "id", detector)
		}
	}

	// XSS should NOT be skipped (different vulnerability class)
	if cf.shouldSkip("id", "xss") {
		t.Error("shouldSkip(id, xss) should be false - different vulnerability class")
	}

	// Different parameter should not be affected
	if cf.shouldSkip("name", "nosql") {
		t.Error("shouldSkip(name, nosql) should be false - different parameter")
	}
}

func TestShouldSkipDetector_SSTIConfirmed(t *testing.T) {
	cf := newConfirmedFindings()

	cf.confirm("tpl", "ssti")

	// XSS and CSTI should be skipped after SSTI confirmed
	if !cf.shouldSkip("tpl", "xss") {
		t.Error("shouldSkip(tpl, xss) should be true after SSTI confirmed")
	}
	if !cf.shouldSkip("tpl", "csti") {
		t.Error("shouldSkip(tpl, csti) should be true after SSTI confirmed")
	}

	// SQLi should NOT be skipped
	if cf.shouldSkip("tpl", "sqli") {
		t.Error("shouldSkip(tpl, sqli) should be false - different class")
	}
}

func TestShouldSkipDetector_CMDIConfirmed(t *testing.T) {
	cf := newConfirmedFindings()

	cf.confirm("cmd", "cmdi")

	// All remaining detectors should be skipped after RCE confirmed
	allDetectors := []string{"sqli", "xss", "ssrf", "lfi", "xxe", "nosql", "ssti", "redirect", "crlf", "ldap", "xpath", "headerinj", "csti", "rfi"}
	for _, detector := range allDetectors {
		if !cf.shouldSkip("cmd", detector) {
			t.Errorf("shouldSkip(cmd, %q) should be true after CMDI (RCE) confirmed", detector)
		}
	}
}

func TestConfirmedFindings_ConcurrentAccess(t *testing.T) {
	cf := newConfirmedFindings()
	done := make(chan struct{})

	// Concurrent writes and reads
	go func() {
		for i := 0; i < 100; i++ {
			cf.confirm("param1", "sqli")
		}
		done <- struct{}{}
	}()

	go func() {
		for i := 0; i < 100; i++ {
			cf.shouldSkip("param1", "nosql")
		}
		done <- struct{}{}
	}()

	<-done
	<-done
}

// TestInternalScanner_GlobalProxyHeadersUserAgent verifies that the
// per-scan Config (Proxy, Headers, UserAgent, Cookies) is propagated to
// EVERY HTTP request the scanner makes — not just the SQLi/classify
// hot paths. Burp Suite integration depends on this, and so does any
// authenticated scan that needs a session cookie or bearer header.
//
// Strategy: a single httptest server doubles as both the target and the
// HTTP proxy. When a client uses the server as a proxy, the request line
// carries an absolute URL (and arrives back at the same handler). We
// then assert that ALL recorded requests carry the configured UA, the
// configured custom header, and arrive via the proxy path (absolute URL).
func TestInternalScanner_GlobalProxyHeadersUserAgent(t *testing.T) {
	const (
		wantUA     = "SKWS-test/9.9"
		wantHdr    = "global-marker"
		wantCookie = "skws-session=abc"
	)

	var (
		mu       sync.Mutex
		total    int
		badUA    int
		badHdr   int
		badCk    int
		notProxy int
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		total++
		if r.Header.Get("User-Agent") != wantUA {
			badUA++
		}
		if r.Header.Get("X-Test-Header") != wantHdr {
			badHdr++
		}
		if !strings.Contains(r.Header.Get("Cookie"), wantCookie) {
			badCk++
		}
		// A proxied request has an absolute URL on the request line.
		if !r.URL.IsAbs() {
			notProxy++
		}
		mu.Unlock()

		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer server.Close()

	// Trim everything to a tight, fast scan but exercise multiple
	// detector code paths so we cover both the SQLi hot path and the
	// "other detector" paths that previously bypassed scanClient.
	config := &InternalScanConfig{
		EnableSQLi:          true,
		EnableXSS:           true,
		EnableSSTI:          true,
		EnableRedirect:      true,
		EnableCRLF:          true,
		EnableHeaderInj:     true,
		EnableSecHeaders:    true,
		EnableTechScan:      false,
		EnableOOB:           false,
		EnableDiscovery:     false,
		MaxPayloadsPerParam: 2,
		RequestTimeout:      5 * time.Second,
	}
	scanner, err := NewInternalScanner(config)
	if err != nil {
		t.Fatalf("NewInternalScanner: %v", err)
	}
	defer scanner.Close()

	target, _ := core.NewTarget(server.URL + "?id=1")

	scanCfg := &Config{
		Headers:   map[string]string{"X-Test-Header": wantHdr},
		Cookies:   wantCookie,
		ProxyURL:  server.URL, // server doubles as proxy
		UserAgent: wantUA,
	}

	if _, err := scanner.Scan(context.Background(), target, scanCfg); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if total == 0 {
		t.Fatal("scanner made zero HTTP requests")
	}
	if badUA != 0 {
		t.Errorf("custom User-Agent missing on %d/%d requests", badUA, total)
	}
	if badHdr != 0 {
		t.Errorf("custom header missing on %d/%d requests", badHdr, total)
	}
	if badCk != 0 {
		t.Errorf("custom cookie missing on %d/%d requests", badCk, total)
	}
	if notProxy != 0 {
		t.Errorf("%d/%d requests bypassed the configured proxy", notProxy, total)
	}
}

func BenchmarkInternalScanner_Scan(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	config := &InternalScanConfig{
		EnableSQLi:          true,
		EnableXSS:           true,
		EnableNoSQL:         true,
		EnableSSTI:          true,
		EnableCORS:          true,
		EnableOOB:           false,
		MaxPayloadsPerParam: 5,
		RequestTimeout:      5 * time.Second,
	}

	scanner, _ := NewInternalScanner(config)
	defer scanner.Close()

	target, _ := core.NewTarget(server.URL + "?id=1")

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = scanner.Scan(ctx, target, nil)
	}
}
