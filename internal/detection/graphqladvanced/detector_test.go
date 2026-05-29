package graphqladvanced

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

func newClient() *scanhttp.Client {
	return scanhttp.NewClient().WithTimeout(5 * time.Second)
}

func TestDetector_NameAndDescription(t *testing.T) {
	d := New(newClient())
	if d.Name() != "graphqladvanced" {
		t.Errorf("Name() = %q, want graphqladvanced", d.Name())
	}
	if d.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestDetector_NilClientIsNoOp(t *testing.T) {
	d := New(nil)
	res, err := d.Detect(context.Background(), "https://example.invalid/graphql", DefaultOptions())
	if err != nil {
		t.Fatalf("Detect with nil client returned error: %v", err)
	}
	if res == nil || res.Vulnerable || len(res.Findings) != 0 {
		t.Errorf("expected empty result on nil client, got %+v", res)
	}
}

// TestDetector_FieldSuggestionRecovery covers the case where introspection
// is disabled but the server still returns "Did you mean ...?" field
// suggestions on typos. graphqladvanced exploits this by issuing a
// typo'd field, harvesting the suggestion, and confirming the real
// field name leaks despite introspection being locked down.
func TestDetector_FieldSuggestionRecovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		// Refuse introspection.
		if strings.Contains(s, "__schema") || strings.Contains(s, "__type") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"errors":[{"message":"introspection disabled"}]}`))
			return
		}
		// Suggest "secretField" when the user types "secretFiel".
		if strings.Contains(s, "secretFiel") && !strings.Contains(s, "secretField") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field \"secretFiel\" on type \"Query\". Did you mean \"secretField\"?"}]}`))
			return
		}
		// Default: no suggestion.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field"}]}`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected field-suggestion recovery to fire; techniques=%v", res.Techniques)
	}
	if !containsTechnique(res.Techniques, "field_suggestion_recovery") {
		t.Errorf("expected technique 'field_suggestion_recovery'; got %v", res.Techniques)
	}
	hasFinding := false
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "Field suggestion") {
			hasFinding = true
			if !contains(f.CWE, "CWE-200") {
				t.Errorf("expected CWE-200 on field-suggestion finding; got %v", f.CWE)
			}
		}
	}
	if !hasFinding {
		t.Error("expected at least one field-suggestion finding")
	}
}

// TestDetector_APQBypass covers the Automatic Persisted Queries fall-
// through misconfig: server accepts an APQ extension with a known-bad
// hash, then ALSO executes the supplied "query" string — bypassing the
// allowlist of pre-registered hashes that APQ is supposed to enforce.
func TestDetector_APQBypass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)
		hasExtensions := req["extensions"] != nil
		hasQuery := req["query"] != nil
		w.Header().Set("Content-Type", "application/json")
		if hasExtensions && hasQuery {
			// Misconfig: execute the query even though APQ should
			// require the hash to match a pre-registered query.
			_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
			return
		}
		// Otherwise, behave correctly — refuse unknown hashes.
		_, _ = w.Write([]byte(`{"errors":[{"message":"PersistedQueryNotFound","extensions":{"code":"PERSISTED_QUERY_NOT_FOUND"}}]}`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected APQ bypass to fire; techniques=%v", res.Techniques)
	}
	if !containsTechnique(res.Techniques, "apq_bypass") {
		t.Errorf("expected technique 'apq_bypass'; got %v", res.Techniques)
	}
}

// TestDetector_GETMutationCSRF flags servers that accept mutations over
// HTTP GET — turning every mutation into a CSRF gadget because GET
// requests can be triggered cross-origin via <img>/<link>/<script>.
func TestDetector_GETMutationCSRF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			q := r.URL.Query().Get("query")
			if strings.Contains(q, "mutation") {
				_, _ = w.Write([]byte(`{"data":{"executedMutation":true}}`))
				return
			}
		}
		_, _ = w.Write([]byte(`{"errors":[{"message":"only POST allowed for mutations"}]}`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected GET-mutation CSRF to fire; techniques=%v", res.Techniques)
	}
	if !containsTechnique(res.Techniques, "get_mutation_csrf") {
		t.Errorf("expected technique 'get_mutation_csrf'; got %v", res.Techniques)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "GET") {
			if f.Severity != core.SeverityHigh {
				t.Errorf("GET-mutation severity = %q, want High", f.Severity)
			}
		}
	}
}

func TestDetector_IncrementalDelivery_MultipartMixed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"errors":[{"message":"POST only"}]}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "@defer") {
			// Servers that support @defer signal it via multipart/mixed.
			w.Header().Set("Content-Type", `multipart/mixed; boundary="-"`)
			_, _ = w.Write([]byte(`---` + "\nContent-Type: application/json\n\n" + `{"data":{"__typename":"Query"},"hasNext":true}` + "\n---" + `--`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !containsTechnique(res.Techniques, "defer_stream_enabled") {
		t.Errorf("expected technique 'defer_stream_enabled', got %v", res.Techniques)
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "@defer") {
			found = true
			if f.Severity != core.SeverityMedium {
				t.Errorf("@defer severity = %q, want Medium", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected an @defer finding")
	}
}

func TestDetector_IncrementalDelivery_HasNextJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "@defer") {
				_, _ = w.Write([]byte(`{"data":{"__typename":"Query"},"hasNext":true,"incremental":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"errors":[{"message":"POST only"}]}`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, _ := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if !containsTechnique(res.Techniques, "defer_stream_enabled") {
		t.Errorf("expected 'defer_stream_enabled' from JSON hasNext envelope, got %v", res.Techniques)
	}
}

func TestDetector_FederationSDL_Disclosure(t *testing.T) {
	sdl := `type Query { user(id:ID!): User } type User @key(fields:\"id\") { id: ID! email: String! adminFlag: Boolean! }`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"errors":[{"message":"POST only"}]}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), "_service") {
			_, _ = w.Write([]byte(`{"data":{"_service":{"sdl":"` + sdl + `"}}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, _ := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if !containsTechnique(res.Techniques, "apollo_federation_sdl_disclosure") {
		t.Errorf("expected 'apollo_federation_sdl_disclosure', got %v", res.Techniques)
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "_service") {
			found = true
			if f.Severity != core.SeverityHigh {
				t.Errorf("SDL disclosure severity = %q, want High", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected an _service finding")
	}
}

func TestDetector_FederationEntities_Disclosure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"errors":[{"message":"POST only"}]}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(string(body), "_entities") {
			_, _ = w.Write([]byte(`{"data":{"_entities":[null]},"errors":[{"message":"No type found for representation"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, _ := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if !containsTechnique(res.Techniques, "apollo_federation_entities_exposed") {
		t.Errorf("expected 'apollo_federation_entities_exposed', got %v", res.Techniques)
	}
}

// TestDetector_HardenedServer_NoFindings ensures a properly-configured
// server triggers no findings. False positives here would be very
// expensive — graphqladvanced runs against any GraphQL-shaped endpoint.
func TestDetector_HardenedServer_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(`{"errors":[{"message":"POST only"}]}`))
			return
		}
		body, _ := io.ReadAll(r.Body)
		s := string(body)
		// Lock down introspection AND field suggestions.
		if strings.Contains(s, "__schema") || strings.Contains(s, "__type") {
			_, _ = w.Write([]byte(`{"errors":[{"message":"introspection disabled"}]}`))
			return
		}
		// Lock down APQ — never execute a query when the hash is unknown.
		var req map[string]interface{}
		_ = json.Unmarshal(body, &req)
		if req["extensions"] != nil {
			_, _ = w.Write([]byte(`{"errors":[{"message":"PersistedQueryNotFound"}]}`))
			return
		}
		// Strict "field not found" — no suggestion text.
		_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field"}]}`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("hardened server flagged: techniques=%v", res.Techniques)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected 0 findings on hardened server, got %d", len(res.Findings))
	}
}

// TestDetector_NonGraphQLEndpoint_NoOp ensures we don't fire on
// arbitrary JSON endpoints that happen to return errors.
func TestDetector_NonGraphQLEndpoint_NoOp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	d := New(newClient())
	res, err := d.Detect(context.Background(), srv.URL, DefaultOptions())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("non-GraphQL endpoint flagged: techniques=%v", res.Techniques)
	}
}

func containsTechnique(list []string, needle string) bool {
	for _, t := range list {
		if t == needle {
			return true
		}
	}
	return false
}

func contains(list []string, needle string) bool {
	for _, h := range list {
		if h == needle {
			return true
		}
	}
	return false
}
