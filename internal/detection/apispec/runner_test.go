package apispec

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// authBypassSpec declares /admin/users requires bearer auth.
const authBypassSpec = `{
  "openapi": "3.0.3",
  "security": [{"bearerAuth": []}],
  "paths": {
    "/admin/users": {
      "get": {"operationId": "listAdminUsers"}
    }
  }
}`

// undocVerbSpec declares only GET on /reports.
const undocVerbSpec = `{
  "openapi": "3.0.3",
  "paths": {
    "/reports": {
      "get": {"operationId": "listReports"}
    }
  }
}`

func TestRun_FlagsUnauthenticatedAccessOnSpecAuthEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// /admin/users returns 200 to anyone — that's the bug we want to flag.
		if r.URL.Path == "/admin/users" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id":1,"name":"alice"}]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	spec, err := Parse([]byte(authBypassSpec))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	r := NewRunner(skwshttp.NewClient())
	res, err := r.Run(context.Background(), spec, srv.URL)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.EndpointsProbed == 0 {
		t.Fatal("expected at least one endpoint probed")
	}
	hit := false
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "Spec-Documented Auth Not Enforced") {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("expected auth-bypass finding, got %+v", res.Findings)
	}
}

func TestRun_FlagsUndocumentedVerb(t *testing.T) {
	var seenVerbs sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenVerbs.Store(r.Method, true)
		// /reports happily handles every verb — the documented GET, plus
		// undocumented PUT/PATCH/DELETE/OPTIONS.
		if r.URL.Path == "/reports" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	spec, _ := Parse([]byte(undocVerbSpec))
	r := NewRunner(skwshttp.NewClient())
	res, _ := r.Run(context.Background(), spec, srv.URL)

	verbs := map[string]bool{}
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "Undocumented HTTP Verb") {
			verbs[f.Parameter] = true
		}
	}
	for _, want := range []string{"PUT", "PATCH", "DELETE", "OPTIONS"} {
		if !verbs[want] {
			t.Errorf("expected undocumented-verb finding for %s, got %v", want, verbs)
		}
	}
}

func TestRun_NoFindingsWhen401Returned(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	spec, _ := Parse([]byte(authBypassSpec))
	r := NewRunner(skwshttp.NewClient())
	res, _ := r.Run(context.Background(), spec, srv.URL)
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "Spec-Documented Auth Not Enforced") {
			t.Errorf("should not flag auth-bypass when server returns 401, got %v", f)
		}
	}
}

func TestRun_NoOpOnNilClientOrSpec(t *testing.T) {
	r := NewRunner(nil)
	res, err := r.Run(context.Background(), &Spec{}, "http://x.test")
	if err != nil {
		t.Fatalf("nil client should not error: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("nil client should yield 0 findings, got %d", len(res.Findings))
	}
}
