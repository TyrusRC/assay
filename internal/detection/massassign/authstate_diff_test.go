package massassign

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

// vulnerableProfileApp persists every field it receives at /api/profile
// (PATCH) including admin/role/verified flags — the canonical mass-
// assignment bug that re-fetch confirmation is built to catch.
type vulnerableProfileApp struct {
	mu      sync.Mutex
	profile map[string]interface{}
	stripPrivileged bool
}

func newVulnerableProfileApp(strip bool) *vulnerableProfileApp {
	return &vulnerableProfileApp{
		profile: map[string]interface{}{
			"name":  "alice",
			"email": "alice@example.com",
		},
		stripPrivileged: strip,
	}
}

func (a *vulnerableProfileApp) handle(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(a.profile)
		return
	}

	if r.Method != "PATCH" && r.Method != "POST" && r.Method != "PUT" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, _ := io.ReadAll(r.Body)
	var incoming map[string]interface{}
	if err := json.Unmarshal(body, &incoming); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if a.stripPrivileged {
		// Safe: only allow a tiny allowlist.
		allow := map[string]bool{"name": true, "email": true}
		for k, v := range incoming {
			if allow[k] {
				a.profile[k] = v
			}
		}
	} else {
		// Vulnerable: persist whatever the client sent.
		for k, v := range incoming {
			a.profile[k] = v
		}
	}

	// Echo the current profile back. The existing single-shot detector
	// would flag this as a "field reflection" finding, but that's NOISY —
	// the new re-fetch primitive only flags when GET-after-PATCH proves
	// the field actually persisted server-side.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(a.profile)
}

func TestDetectWithReFetch_Vulnerable(t *testing.T) {
	app := newVulnerableProfileApp(false)
	srv := httptest.NewServer(http.HandlerFunc(app.handle))
	defer srv.Close()

	d := New(internalhttp.NewClient())
	opts := DefaultAuthStateDiffOptions()
	opts.WriteURL = srv.URL + "/api/profile"
	opts.FetchURL = srv.URL + "/api/profile"
	opts.BaseBody = `{"name":"alice","email":"alice@example.com"}`

	res, err := d.DetectWithReFetch(context.Background(), opts)
	if err != nil {
		t.Fatalf("DetectWithReFetch: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected mass-assignment finding; got %+v", res.Findings)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	for _, f := range res.Findings {
		if f.Severity != core.SeverityCritical {
			t.Errorf("re-fetch confirmation should be Critical; got %s", f.Severity)
		}
		if !strings.Contains(f.Description, "re-fetching state") {
			t.Errorf("description should mention re-fetch confirmation; got %q", f.Description)
		}
	}
}

// TestDetectWithReFetch_Safe: an allowlist-binding app strips privileged
// fields → no finding (FP guard for the existing reflection-only signal).
func TestDetectWithReFetch_Safe(t *testing.T) {
	app := newVulnerableProfileApp(true)
	srv := httptest.NewServer(http.HandlerFunc(app.handle))
	defer srv.Close()

	d := New(internalhttp.NewClient())
	opts := DefaultAuthStateDiffOptions()
	opts.WriteURL = srv.URL + "/api/profile"
	opts.FetchURL = srv.URL + "/api/profile"
	opts.BaseBody = `{"name":"alice","email":"alice@example.com"}`

	res, err := d.DetectWithReFetch(context.Background(), opts)
	if err != nil {
		t.Fatalf("DetectWithReFetch: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("safe app must not flag; got %+v", res.Findings)
	}
}

// TestDetectWithReFetch_EchoOnlyDoesNotFlag: the FP that motivates this
// whole primitive — a server that ECHOES whatever JSON it receives in
// the response body but does NOT persist it. Re-fetching the profile
// should show the original state, so no finding fires.
func TestDetectWithReFetch_EchoOnlyDoesNotFlag(t *testing.T) {
	mu := &sync.Mutex{}
	persisted := map[string]interface{}{
		"name":  "alice",
		"email": "alice@example.com",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(persisted)
			return
		}
		// PATCH: echo body verbatim but DON'T persist anything.
		body, _ := io.ReadAll(r.Body)
		var inc map[string]interface{}
		_ = json.Unmarshal(body, &inc)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(inc)
	}))
	defer srv.Close()

	d := New(internalhttp.NewClient())
	opts := DefaultAuthStateDiffOptions()
	opts.WriteURL = srv.URL + "/api/profile"
	opts.FetchURL = srv.URL + "/api/profile"
	opts.BaseBody = `{"name":"alice","email":"alice@example.com"}`

	res, err := d.DetectWithReFetch(context.Background(), opts)
	if err != nil {
		t.Fatalf("DetectWithReFetch: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("echo-only response (not persisted) must NOT flag; got %+v", res.Findings)
	}
}

// TestDetectWithReFetch_RequiresInputs pins input-validation errors.
func TestDetectWithReFetch_RequiresInputs(t *testing.T) {
	d := New(internalhttp.NewClient())
	if _, err := d.DetectWithReFetch(context.Background(), AuthStateDiffOptions{
		FetchURL: "http://x", BaseBody: "{}",
	}); err == nil {
		t.Error("missing WriteURL should error")
	}
	if _, err := d.DetectWithReFetch(context.Background(), AuthStateDiffOptions{
		WriteURL: "http://x", BaseBody: "{}",
	}); err == nil {
		t.Error("missing FetchURL should error")
	}
	if _, err := d.DetectWithReFetch(context.Background(), AuthStateDiffOptions{
		WriteURL: "http://x", FetchURL: "http://x",
	}); err == nil {
		t.Error("missing BaseBody should error")
	}
}

// TestPrivilegeStuck pins the analyzer.
func TestPrivilegeStuck(t *testing.T) {
	cases := []struct {
		name   string
		before map[string]interface{}
		after  map[string]interface{}
		field  string
		want   bool
	}{
		{"absent → admin true",
			map[string]interface{}{},
			map[string]interface{}{"isAdmin": true},
			"isAdmin", true},
		{"false → true (real escalation)",
			map[string]interface{}{"isAdmin": false},
			map[string]interface{}{"isAdmin": true},
			"isAdmin", true},
		{"role normal → admin",
			map[string]interface{}{"role": "user"},
			map[string]interface{}{"role": "admin"},
			"role", true},
		{"absent → false (no escalation)",
			map[string]interface{}{},
			map[string]interface{}{"isAdmin": false},
			"isAdmin", false},
		{"already true (no transition)",
			map[string]interface{}{"isAdmin": true},
			map[string]interface{}{"isAdmin": true},
			"isAdmin", false},
		{"field absent in after",
			map[string]interface{}{"isAdmin": false},
			map[string]interface{}{},
			"isAdmin", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := privilegeStuck(tc.before, tc.after, tc.field); got != tc.want {
				t.Errorf("privilegeStuck = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestInjectField(t *testing.T) {
	got, err := injectField(`{"name":"alice"}`, "isAdmin", true)
	if err != nil {
		t.Fatalf("injectField: %v", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(got), &obj); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if obj["isAdmin"] != true {
		t.Errorf("isAdmin not injected; got %v", obj["isAdmin"])
	}
	if obj["name"] != "alice" {
		t.Errorf("name not preserved; got %v", obj["name"])
	}

	if _, err := injectField(`not json`, "x", 1); err == nil {
		t.Error("non-JSON baseBody should error")
	}
}
