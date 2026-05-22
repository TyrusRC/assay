package graphqldos

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	scanhttp "github.com/TyrusRC/assay/internal/http"
)

func newClient() *scanhttp.Client {
	return scanhttp.NewClient().WithTimeout(5 * time.Second)
}

func TestDetector_NameAndDescription(t *testing.T) {
	d := New(newClient())
	if d.Name() != "graphqldos" {
		t.Errorf("Name() = %q, want graphqldos", d.Name())
	}
	if d.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestDetector_NilClientIsNoOp(t *testing.T) {
	d := New(nil)
	res, err := d.Detect(context.Background(), "https://example.invalid/graphql", DefaultOptions())
	if err != nil {
		t.Fatalf("nil client: %v", err)
	}
	if res == nil || res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on nil client, got %+v", res)
	}
}

// TestDetector_NotGraphQL_NoOp covers a non-GraphQL endpoint — the
// detector's self-gate should bail and emit no findings.
func TestDetector_NotGraphQL_NoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<h1>not graphql</h1>"))
	}))
	defer srv.Close()

	res, err := New(newClient()).Detect(context.Background(), srv.URL+"/graphql", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("non-graphql flagged: %+v", res)
	}
}

// TestDetector_AliasAmplification_Flags covers a server that returns a
// data envelope no matter how many aliases the client packs into one
// query.
func TestDetector_AliasAmplification_Flags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
		_ = r
	}))
	defer srv.Close()

	res, err := New(newClient()).Detect(context.Background(), srv.URL+"/graphql", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected vulnerability; techniques=%v", res.Techniques)
	}
	if !containsTechnique(res.Techniques, "alias_amplification") {
		t.Errorf("expected alias_amplification; got %v", res.Techniques)
	}
}

// TestDetector_AliasLimited_NoFlag covers a server that rejects
// queries with too many aliases.
func TestDetector_AliasLimited_NoFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := readBody(r)
		w.Header().Set("Content-Type", "application/json")
		// Count alias declarations via the literal "a0:" pattern that
		// the detector's amplification probe emits. The depth and batch
		// probes don't carry "a0:", so the gate probe and those probes
		// pass through.
		if strings.Contains(body, "a99:") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":[{"message":"too many aliases"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer srv.Close()

	res, err := New(newClient()).Detect(context.Background(), srv.URL+"/graphql", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if containsTechnique(res.Techniques, "alias_amplification") {
		t.Errorf("expected no alias_amplification on rate-limited server; got %v", res.Techniques)
	}
}

// TestDetector_BatchedQuery_Flags covers a server that happily
// processes an array of N queries in a single request.
func TestDetector_BatchedQuery_Flags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := readBody(r)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(strings.TrimSpace(body), "[") {
			_, _ = w.Write([]byte(`[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer srv.Close()

	res, err := New(newClient()).Detect(context.Background(), srv.URL+"/graphql", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !containsTechnique(res.Techniques, "batched_query_allowed") {
		t.Errorf("expected batched_query_allowed; got %v", res.Techniques)
	}
}

// TestDetector_DepthBomb_Flags covers a server that doesn't reject
// queries with deep AST nesting.
func TestDetector_DepthBomb_Flags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer srv.Close()

	res, err := New(newClient()).Detect(context.Background(), srv.URL+"/graphql", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !containsTechnique(res.Techniques, "query_depth_unbounded") {
		t.Errorf("expected query_depth_unbounded; got %v", res.Techniques)
	}
}

func readBody(r *http.Request) (string, error) {
	defer r.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	return sb.String(), nil
}

func containsTechnique(list []string, needle string) bool {
	for _, s := range list {
		if s == needle {
			return true
		}
	}
	return false
}
