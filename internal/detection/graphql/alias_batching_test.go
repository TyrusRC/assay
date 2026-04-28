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

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	internalhttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

// vulnerableGraphQL simulates an Apollo-style server that has per-request
// rate limiting but happily processes any number of aliased fields inside
// one request — the canonical alias-batching bypass.
func vulnerableGraphQL() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct{ Query string }
		_ = json.Unmarshal(raw, &req)

		// Extract every alias name appearing as `<alias>: login` to
		// simulate per-alias execution.
		aliases := []string{}
		lines := strings.Split(req.Query, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if i := strings.Index(line, ": login"); i > 0 {
				aliases = append(aliases, line[:i])
			}
		}
		if len(aliases) == 0 {
			// Single-call ground truth: respond with a wrong-password style entry.
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"data":{"login":null},"errors":[{"message":"invalid credentials"}]}`)
			return
		}

		// Aliased batch: pretend every alias executed and got "invalid credentials"
		// (rate limit was supposed to reject after 1 attempt, but it's not enforced
		// at the alias level).
		data := map[string]interface{}{}
		for _, a := range aliases {
			data[a] = map[string]interface{}{"token": nil, "user": nil}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
	}))
}

// rateLimitedGraphQL simulates a server that DOES enforce alias-level
// rate limits — it counts aliased login calls and refuses requests
// containing more than 1 such call.
func rateLimitedGraphQL() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		count := strings.Count(string(raw), ": login")
		if count > 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"errors":[{"message":"rate limit: too many login attempts"}]}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"login":null},"errors":[{"message":"invalid credentials"}]}`)
	}))
}

// TestDetectAliasBatching_Vulnerable: vulnerable server processes all 100
// aliases → Critical finding.
func TestDetectAliasBatching_Vulnerable(t *testing.T) {
	srv := vulnerableGraphQL()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectAliasBatching(context.Background(), srv.URL+"/graphql", DefaultAliasBatchingOptions())
	if err != nil {
		t.Fatalf("DetectAliasBatching: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected a finding on vulnerable GraphQL server")
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityCritical {
		t.Errorf("100/100 aliases executed should grade Critical; got %s", f.Severity)
	}
	if !strings.Contains(f.Description, "alias") {
		t.Errorf("description should mention aliasing; got %q", f.Description)
	}
}

// TestDetectAliasBatching_RateLimitEnforced: server that rate-limits at the
// alias level returns 429 → no finding.
func TestDetectAliasBatching_RateLimitEnforced(t *testing.T) {
	srv := rateLimitedGraphQL()
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectAliasBatching(context.Background(), srv.URL+"/graphql", DefaultAliasBatchingOptions())
	if err != nil {
		t.Fatalf("DetectAliasBatching: %v", err)
	}
	if len(res.Findings) > 0 {
		t.Fatalf("rate-limited server must not flag; got %+v", res.Findings)
	}
}

// TestDetectAliasBatching_PartialPass: server that processes some but not
// most aliases (e.g. limits to 50 but caller sent 100) should grade High,
// not Critical.
func TestDetectAliasBatching_PartialPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct{ Query string }
		_ = json.Unmarshal(raw, &req)
		aliases := []string{}
		for _, line := range strings.Split(req.Query, "\n") {
			line = strings.TrimSpace(line)
			if i := strings.Index(line, ": login"); i > 0 {
				aliases = append(aliases, line[:i])
			}
		}
		if len(aliases) == 0 {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"data":{"login":null},"errors":[{"message":"invalid credentials"}]}`)
			return
		}
		// Process at most 50 — return data only for those, errors for the rest.
		data := map[string]interface{}{}
		for i, a := range aliases {
			if i < 50 {
				data[a] = map[string]interface{}{"token": nil}
			} else {
				data[a] = nil
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": data})
	}))
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectAliasBatching(context.Background(), srv.URL+"/graphql", DefaultAliasBatchingOptions())
	if err != nil {
		t.Fatalf("DetectAliasBatching: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected a finding even on partial bypass")
	}
	if res.Findings[0].Severity != core.SeverityHigh {
		t.Errorf("50%% pass rate should grade High, not %s", res.Findings[0].Severity)
	}
}

// TestDetectAliasBatching_NonGraphQLEndpoint: a 404 / non-JSON response
// must not flag.
func TestDetectAliasBatching_NonGraphQLEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	d := New(internalhttp.NewClient())
	res, err := d.DetectAliasBatching(context.Background(), srv.URL+"/graphql", DefaultAliasBatchingOptions())
	if err != nil {
		t.Fatalf("DetectAliasBatching: %v", err)
	}
	if len(res.Findings) > 0 {
		t.Fatalf("non-GraphQL endpoint must not flag; got %+v", res.Findings)
	}
}

// TestReplacePassword_EscapesQuotes confirms the password substitution
// escapes embedded quotes/backslashes — without this, a wordlist entry
// containing a quote would corrupt the GraphQL string literal and the
// whole query would fail to parse.
func TestReplacePassword_EscapesQuotes(t *testing.T) {
	got := replacePassword(`(password: "PASSWORD")`, `bad"pw`)
	if !strings.Contains(got, `"bad\"pw"`) {
		t.Errorf("quote in password not escaped; got %q", got)
	}
	got2 := replacePassword(`(password: "PASSWORD")`, `bs\back`)
	if !strings.Contains(got2, `"bs\\back"`) {
		t.Errorf("backslash in password not escaped; got %q", got2)
	}
}
