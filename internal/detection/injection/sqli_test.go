package injection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestSQLiDetector_Name(t *testing.T) {
	detector := NewSQLiDetector()
	if detector.Name() != "sqli" {
		t.Errorf("Name() = %q, want %q", detector.Name(), "sqli")
	}
}

func TestSQLiDetector_Description(t *testing.T) {
	detector := NewSQLiDetector()
	desc := detector.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}
}

func TestSQLiDetector_AnalyzeResponse_ErrorBased(t *testing.T) {
	detector := NewSQLiDetector()

	tests := []struct {
		name     string
		response string
		detected bool
	}{
		{
			name:     "MySQL syntax error",
			response: "You have an error in your SQL syntax; check the manual",
			detected: true,
		},
		{
			name:     "PostgreSQL error",
			response: "ERROR: syntax error at or near",
			detected: true,
		},
		{
			name:     "MSSQL error",
			response: "Unclosed quotation mark after the character string",
			detected: true,
		},
		{
			name:     "Oracle error",
			response: "ORA-01756: quoted string not properly terminated",
			detected: true,
		},
		{
			name:     "SQLite error",
			response: "SQLITE_ERROR: near \"'\": syntax error",
			detected: true,
		},
		{
			name:     "generic SQL error",
			response: "SQL syntax error in query",
			detected: true,
		},
		{
			name:     "normal response",
			response: "Welcome to our website! Here is your content.",
			detected: false,
		},
		{
			name:     "empty response",
			response: "",
			detected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.AnalyzeResponse(tt.response)
			if result.IsVulnerable != tt.detected {
				t.Errorf("AnalyzeResponse() detected = %v, want %v", result.IsVulnerable, tt.detected)
			}
			if tt.detected && result.DetectionType == "" {
				t.Error("DetectionType should not be empty when vulnerable")
			}
		})
	}
}

func TestSQLiDetector_GetPayloads(t *testing.T) {
	detector := NewSQLiDetector()
	payloads := detector.GetPayloads()

	if len(payloads) == 0 {
		t.Error("GetPayloads() should return at least one payload")
	}

	// Check that basic SQLi payloads are included
	basicPayloads := []string{"'", "\"", "' OR '1'='1", "1 OR 1=1"}
	for _, bp := range basicPayloads {
		found := false
		for _, p := range payloads {
			if p == bp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected payload %q not found in GetPayloads()", bp)
		}
	}
}

func TestSQLiDetector_GetContextPayloads(t *testing.T) {
	detector := NewSQLiDetector()

	tests := []struct {
		name        string
		context     PayloadContext
		minPayloads int
	}{
		{
			name:        "string context",
			context:     ContextString,
			minPayloads: 3,
		},
		{
			name:        "numeric context",
			context:     ContextNumeric,
			minPayloads: 2,
		},
		{
			name:        "unknown context",
			context:     ContextUnknown,
			minPayloads: 5, // Should return more payloads for unknown context
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := detector.GetContextPayloads(tt.context)
			if len(payloads) < tt.minPayloads {
				t.Errorf("GetContextPayloads(%v) returned %d payloads, want at least %d",
					tt.context, len(payloads), tt.minPayloads)
			}
		})
	}
}

func TestSQLiDetector_DetectDBType(t *testing.T) {
	detector := NewSQLiDetector()

	tests := []struct {
		name     string
		response string
		dbType   DatabaseType
	}{
		{
			name:     "MySQL error",
			response: "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
			dbType:   DBMySQL,
		},
		{
			name:     "PostgreSQL error",
			response: "ERROR: syntax error at or near \"'\"",
			dbType:   DBPostgreSQL,
		},
		{
			name:     "MSSQL error",
			response: "Microsoft SQL Server error",
			dbType:   DBMSSQL,
		},
		{
			name:     "Oracle error",
			response: "ORA-01756: quoted string not properly terminated",
			dbType:   DBOracle,
		},
		{
			name:     "SQLite error",
			response: "SQLITE_ERROR",
			dbType:   DBSQLite,
		},
		{
			name:     "unknown database",
			response: "An error occurred while processing your request",
			dbType:   DBUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbType := detector.DetectDBType(tt.response)
			if dbType != tt.dbType {
				t.Errorf("DetectDBType() = %v, want %v", dbType, tt.dbType)
			}
		})
	}
}

func TestAnalysisResult(t *testing.T) {
	result := &AnalysisResult{
		IsVulnerable:  true,
		DetectionType: "error-based",
		Confidence:    0.9,
		Evidence:      "SQL syntax error",
		DatabaseType:  DBMySQL,
	}

	if !result.IsVulnerable {
		t.Error("IsVulnerable should be true")
	}
	if result.DetectionType != "error-based" {
		t.Errorf("DetectionType = %q, want %q", result.DetectionType, "error-based")
	}
	if result.Confidence != 0.9 {
		t.Errorf("Confidence = %f, want %f", result.Confidence, 0.9)
	}
}

func TestPayloadContext_String(t *testing.T) {
	tests := []struct {
		context PayloadContext
		want    string
	}{
		{ContextString, "string"},
		{ContextNumeric, "numeric"},
		{ContextUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if tt.context.String() != tt.want {
				t.Errorf("String() = %q, want %q", tt.context.String(), tt.want)
			}
		})
	}
}

// blindSQLiServer simulates a string-context boolean-blind SQLi sink.
// The vulnerable parameter is "searchTerm". The original/baseline value
// returns "no products"; a payload that makes WHERE always-true returns
// the full catalog, while always-false returns "no products" again.
func blindSQLiServer(param string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)
		// Always-true variants leak the full catalog.
		isTrue := strings.Contains(v, "' AND '1'='1") ||
			strings.Contains(v, "' OR '1'='1") ||
			strings.Contains(v, "1 OR 1=1") ||
			strings.Contains(v, "1 AND 1=1")
		if isTrue {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body>
<h1>Products</h1>
<ul>
<li>Lemon — $2</li>
<li>Lime — $3</li>
<li>Orange — $4</li>
<li>Mint — $1</li>
<li>Sugar — $1</li>
</ul></body></html>`))
			return
		}
		// Everything else (baseline + false) returns "no products".
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h1>Products</h1><p>No products match.</p></body></html>`))
	}))
}

// stableServer always returns the exact same body — no parameter affects it.
// Used to verify the boolean detector does NOT false-positive.
func stableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h1>Static page</h1><p>Always the same.</p></body></html>`))
	}))
}

func TestSQLiDetector_DetectBoolean_StringContext(t *testing.T) {
	srv := blindSQLiServer("searchTerm")
	defer srv.Close()

	client := skwshttp.NewClient()
	detector := NewSQLiDetector()

	target := srv.URL + "/?searchTerm=test"
	res, err := detector.DetectBoolean(context.Background(), client, target, "searchTerm", "GET")
	if err != nil {
		t.Fatalf("DetectBoolean returned error: %v", err)
	}
	if !res.IsVulnerable {
		t.Fatalf("expected vulnerable=true on simulated blind SQLi, got false")
	}
	if res.DetectionType != "boolean-based" {
		t.Errorf("DetectionType = %q, want %q", res.DetectionType, "boolean-based")
	}
	if res.TruePayload == "" || res.FalsePayload == "" {
		t.Errorf("TruePayload/FalsePayload should be populated; got %q / %q",
			res.TruePayload, res.FalsePayload)
	}
	if res.Confidence <= 0.0 {
		t.Errorf("Confidence should be > 0 on detected differential; got %f", res.Confidence)
	}
}

// portswiggerCategoryServer simulates the PortSwigger blind-SQLi shape:
//   - baseline (`category=Gifts`) returns Gifts products
//   - append AND 1=1 (`category=Gifts' AND '1'='1`) keeps matching Gifts → ≈ baseline
//   - append AND 1=2 (`category=Gifts' AND '1'='2`) matches nothing → empty
//
// The detector must accept the OPPOSITE differential direction (baseline ≈
// true, baseline ≠ false). This test fails on the original BooleanDifferential
// semantics and passes only with the bidirectional rewrite.
// portswiggerCategoryServer simulates `WHERE category='<input>'` exactly:
// only inputs whose category-string segment matches a known category return
// rows. Replace-style payloads (e.g. `' AND '1'='1`) clear the category and
// hit no rows, mirroring real-world behavior — so only the APPEND shape can
// produce the boolean differential.
func portswiggerCategoryServer(param string) *httptest.Server {
	knownCategories := []string{"Gifts", "Pets", "Tech"}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get(param)

		// Detect category prefix (required for any row to match).
		var category string
		for _, c := range knownCategories {
			if strings.HasPrefix(v, c) {
				category = c
				break
			}
		}
		if category == "" {
			// No matching category prefix → empty result, regardless of suffix.
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><h1>Category</h1><p>No products in this category.</p></body></html>`))
			return
		}

		// Suffix is everything after the category. Empty suffix = baseline.
		suffix := strings.TrimPrefix(v, category)
		if suffix == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><h1>Category: ` + category + `</h1>
<ul><li>Mug</li><li>Card</li><li>Pen</li></ul></body></html>`))
			return
		}

		// Suffix exists → simulate the SQL injection: parse the AND/OR clause.
		// `' AND '1'='1`/`' AND '1'='2` style.
		hasTrue := strings.Contains(suffix, "AND '1'='1") || strings.Contains(suffix, "AND 1=1") ||
			strings.Contains(suffix, "OR '1'='1") || strings.Contains(suffix, "OR 1=1")
		hasFalse := strings.Contains(suffix, "AND '1'='2") || strings.Contains(suffix, "AND 1=2") ||
			strings.Contains(suffix, "OR '1'='2") || strings.Contains(suffix, "OR 1=2")

		if hasTrue && !hasFalse {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><body><h1>Category: ` + category + `</h1>
<ul><li>Mug</li><li>Card</li><li>Pen</li></ul></body></html>`))
			return
		}
		// Anything else (false-clause, syntax-error suffix) → empty result.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h1>Category: ` + category + `</h1><p>No products in this category.</p></body></html>`))
	}))
}

func TestSQLiDetector_DetectBoolean_AppendStyle(t *testing.T) {
	srv := portswiggerCategoryServer("category")
	defer srv.Close()

	client := skwshttp.NewClient()
	detector := NewSQLiDetector()

	target := srv.URL + "/?category=Gifts"
	res, err := detector.DetectBoolean(context.Background(), client, target, "category", "GET")
	if err != nil {
		t.Fatalf("DetectBoolean returned error: %v", err)
	}
	if !res.IsVulnerable {
		t.Fatalf("expected vulnerable=true on PortSwigger-style append SQLi, got false")
	}
	if !strings.HasPrefix(res.TruePayload, "Gifts") {
		t.Errorf("expected TruePayload to be append-style starting with 'Gifts', got %q", res.TruePayload)
	}
	if !strings.HasPrefix(res.FalsePayload, "Gifts") {
		t.Errorf("expected FalsePayload to be append-style starting with 'Gifts', got %q", res.FalsePayload)
	}
}

func TestSQLiDetector_DetectBoolean_NoFalsePositive(t *testing.T) {
	srv := stableServer()
	defer srv.Close()

	client := skwshttp.NewClient()
	detector := NewSQLiDetector()

	target := srv.URL + "/?searchTerm=test"
	res, err := detector.DetectBoolean(context.Background(), client, target, "searchTerm", "GET")
	if err != nil {
		t.Fatalf("DetectBoolean returned error: %v", err)
	}
	if res.IsVulnerable {
		t.Errorf("expected vulnerable=false on stable server, got true (payloads: T=%q F=%q)",
			res.TruePayload, res.FalsePayload)
	}
}

func TestDatabaseType_String(t *testing.T) {
	tests := []struct {
		dbType DatabaseType
		want   string
	}{
		{DBMySQL, "mysql"},
		{DBPostgreSQL, "postgresql"},
		{DBMSSQL, "mssql"},
		{DBOracle, "oracle"},
		{DBSQLite, "sqlite"},
		{DBUnknown, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if tt.dbType.String() != tt.want {
				t.Errorf("String() = %q, want %q", tt.dbType.String(), tt.want)
			}
		})
	}
}
