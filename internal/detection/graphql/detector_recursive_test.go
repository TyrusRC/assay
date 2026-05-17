package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// --- shared helpers ---------------------------------------------------------

// readBodyAsQuery reads a GraphQL JSON request and returns the embedded query.
func readBodyAsQuery(r *http.Request) string {
	raw, _ := io.ReadAll(r.Body)
	var req struct {
		Query string `json:"query"`
	}
	_ = json.Unmarshal(raw, &req)
	return req.Query
}

// writeJSON helper.
func writeJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, body)
}

// --- DetectRecursiveFragments ----------------------------------------------

// recursiveFragmentVulnerableServer simulates a server that has no
// cycle/depth protection — when it sees a recursive fragment it expands
// it ~50 levels and produces a very large body. We also stall a bit on
// recursive queries to simulate the CPU cost.
func recursiveFragmentVulnerableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readBodyAsQuery(r)
		// Baseline single-field probe: small body, near-zero latency.
		if !strings.Contains(q, "fragment") {
			writeJSON(w, `{"data":{"__typename":"Query"}}`)
			return
		}
		// Recursive fragment probe: stall, then return a body
		// proportional in size to a ~50-level expansion.
		time.Sleep(80 * time.Millisecond)
		// Build a deeply nested JSON body to mimic expansion.
		var b strings.Builder
		b.WriteString(`{"data":{"user":`)
		for i := 0; i < 200; i++ {
			b.WriteString(`{"friends":[`)
		}
		b.WriteString(`null`)
		for i := 0; i < 200; i++ {
			b.WriteString(`]}`)
		}
		b.WriteString(`}}`)
		writeJSON(w, b.String())
	}))
}

// recursiveFragmentSafeServer simulates a server with cycle detection —
// it rejects the recursive fragment with a fast, small error response,
// indistinguishable in size/time from the baseline.
func recursiveFragmentSafeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readBodyAsQuery(r)
		if strings.Contains(q, "fragment") {
			writeJSON(w, `{"errors":[{"message":"Cannot spread fragment F within itself"}]}`)
			return
		}
		writeJSON(w, `{"data":{"__typename":"Query"}}`)
	}))
}

func TestDetectRecursiveFragments_Vulnerable(t *testing.T) {
	srv := recursiveFragmentVulnerableServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectRecursiveFragments(context.Background(), srv.URL+"/graphql", DefaultRecursiveOptions())
	if err != nil {
		t.Fatalf("DetectRecursiveFragments: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected a finding on vulnerable server")
	}
	f := res.Findings[0]
	if f.Type != "GraphQL Recursive Fragment Cost" {
		t.Errorf("finding type = %q, want %q", f.Type, "GraphQL Recursive Fragment Cost")
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("severity = %s, want High", f.Severity)
	}
	if f.Tool != "graphql-recursive-detector" {
		t.Errorf("tool = %s, want graphql-recursive-detector", f.Tool)
	}
	if !containsAny(f.Top10, "A02:2025") {
		t.Errorf("Top10 missing A05:2025: %v", f.Top10)
	}
	if !containsAny(f.APITop10, "API4:2023") {
		t.Errorf("APITop10 missing API4:2023: %v", f.APITop10)
	}
	if !containsAny(f.CWE, "CWE-400") || !containsAny(f.CWE, "CWE-770") {
		t.Errorf("CWE missing CWE-400/CWE-770: %v", f.CWE)
	}
}

func TestDetectRecursiveFragments_Safe(t *testing.T) {
	srv := recursiveFragmentSafeServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectRecursiveFragments(context.Background(), srv.URL+"/graphql", DefaultRecursiveOptions())
	if err != nil {
		t.Fatalf("DetectRecursiveFragments: %v", err)
	}
	if len(res.Findings) > 0 {
		t.Fatalf("safe server must not flag; got %+v", res.Findings)
	}
}

// --- DetectTypeRecursion ----------------------------------------------------

// typeRecursionVulnerableServer accepts a deeply-chained __type query and
// returns a large, slow response.
func typeRecursionVulnerableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readBodyAsQuery(r)
		// Baseline single-field probe — small/fast.
		if !strings.Contains(q, "__type") {
			writeJSON(w, `{"data":{"__typename":"Query"}}`)
			return
		}
		// Approximate cost by chain depth.
		depth := strings.Count(q, "fields")
		time.Sleep(time.Duration(depth) * 10 * time.Millisecond)
		var b strings.Builder
		b.WriteString(`{"data":{"__type":`)
		for i := 0; i < depth*30; i++ {
			b.WriteString(`{"fields":[`)
		}
		b.WriteString(`null`)
		for i := 0; i < depth*30; i++ {
			b.WriteString(`]}`)
		}
		b.WriteString(`}}`)
		writeJSON(w, b.String())
	}))
}

func typeRecursionSafeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readBodyAsQuery(r)
		if strings.Contains(q, "__type") {
			writeJSON(w, `{"errors":[{"message":"introspection disabled"}]}`)
			return
		}
		writeJSON(w, `{"data":{"__typename":"Query"}}`)
	}))
}

func TestDetectTypeRecursion_Vulnerable(t *testing.T) {
	srv := typeRecursionVulnerableServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectTypeRecursion(context.Background(), srv.URL+"/graphql", DefaultRecursiveOptions())
	if err != nil {
		t.Fatalf("DetectTypeRecursion: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected a finding on vulnerable __type recursion")
	}
	f := res.Findings[0]
	if f.Type != "GraphQL Type Introspection Recursion" {
		t.Errorf("finding type = %q", f.Type)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("severity = %s, want High", f.Severity)
	}
}

func TestDetectTypeRecursion_Safe(t *testing.T) {
	srv := typeRecursionSafeServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectTypeRecursion(context.Background(), srv.URL+"/graphql", DefaultRecursiveOptions())
	if err != nil {
		t.Fatalf("DetectTypeRecursion: %v", err)
	}
	if len(res.Findings) > 0 {
		t.Fatalf("safe server must not flag; got %+v", res.Findings)
	}
}

// --- DetectFieldDuplicationAmplification ------------------------------------

// fieldDuplicationVulnerableServer doesn't dedupe aliased fields — body
// grows linearly with alias count.
func fieldDuplicationVulnerableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readBodyAsQuery(r)
		// Count aliases like `a0: user`, `a1: user`, ...
		count := strings.Count(q, ": user(")
		if count <= 1 {
			writeJSON(w, `{"data":{"user":{"id":"1","name":"alice"}}}`)
			return
		}
		data := make(map[string]interface{}, count)
		for i := 0; i < count; i++ {
			data[fmt.Sprintf("a%d", i)] = map[string]string{"id": "1", "name": "alice"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
	}))
}

func fieldDuplicationSafeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readBodyAsQuery(r)
		count := strings.Count(q, ": user(")
		if count > 5 {
			w.WriteHeader(http.StatusTooManyRequests)
			writeJSON(w, `{"errors":[{"message":"alias count limit exceeded"}]}`)
			return
		}
		writeJSON(w, `{"data":{"user":{"id":"1","name":"alice"}}}`)
	}))
}

func TestDetectFieldDuplicationAmplification_Vulnerable(t *testing.T) {
	srv := fieldDuplicationVulnerableServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectFieldDuplicationAmplification(context.Background(), srv.URL+"/graphql", DefaultRecursiveOptions())
	if err != nil {
		t.Fatalf("DetectFieldDuplicationAmplification: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected a finding on duplication amplification")
	}
	f := res.Findings[0]
	if f.Type != "GraphQL Field Duplication Amplification" {
		t.Errorf("finding type = %q", f.Type)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("severity = %s, want High", f.Severity)
	}
}

func TestDetectFieldDuplicationAmplification_Safe(t *testing.T) {
	srv := fieldDuplicationSafeServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectFieldDuplicationAmplification(context.Background(), srv.URL+"/graphql", DefaultRecursiveOptions())
	if err != nil {
		t.Fatalf("DetectFieldDuplicationAmplification: %v", err)
	}
	if len(res.Findings) > 0 {
		t.Fatalf("safe server must not flag; got %+v", res.Findings)
	}
}

// --- DetectDirectiveOverload -----------------------------------------------

func directiveOverloadVulnerableServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readBodyAsQuery(r)
		dirCount := strings.Count(q, "@include") + strings.Count(q, "@skip")
		if dirCount == 0 {
			writeJSON(w, `{"data":{"__typename":"Query"}}`)
			return
		}
		// Simulate cost proportional to directive count.
		time.Sleep(time.Duration(dirCount) * time.Millisecond)
		var b strings.Builder
		b.WriteString(`{"data":{"node":`)
		for i := 0; i < dirCount*5; i++ {
			b.WriteString(`{"x":`)
		}
		b.WriteString(`null`)
		for i := 0; i < dirCount*5; i++ {
			b.WriteString(`}`)
		}
		b.WriteString(`}}`)
		writeJSON(w, b.String())
	}))
}

func directiveOverloadSafeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := readBodyAsQuery(r)
		if strings.Contains(q, "@include") || strings.Contains(q, "@skip") {
			dirCount := strings.Count(q, "@include") + strings.Count(q, "@skip")
			if dirCount > 5 {
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, `{"errors":[{"message":"too many directives"}]}`)
				return
			}
		}
		writeJSON(w, `{"data":{"__typename":"Query"}}`)
	}))
}

func TestDetectDirectiveOverload_Vulnerable(t *testing.T) {
	srv := directiveOverloadVulnerableServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectDirectiveOverload(context.Background(), srv.URL+"/graphql", DefaultRecursiveOptions())
	if err != nil {
		t.Fatalf("DetectDirectiveOverload: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected a finding on directive overload")
	}
	f := res.Findings[0]
	if f.Type != "GraphQL Directive Overload" {
		t.Errorf("finding type = %q", f.Type)
	}
	if f.Severity != core.SeverityHigh {
		t.Errorf("severity = %s, want High", f.Severity)
	}
}

func TestDetectDirectiveOverload_Safe(t *testing.T) {
	srv := directiveOverloadSafeServer()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectDirectiveOverload(context.Background(), srv.URL+"/graphql", DefaultRecursiveOptions())
	if err != nil {
		t.Fatalf("DetectDirectiveOverload: %v", err)
	}
	if len(res.Findings) > 0 {
		t.Fatalf("safe server must not flag; got %+v", res.Findings)
	}
}

// --- helpers ----------------------------------------------------------------

func containsAny(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
