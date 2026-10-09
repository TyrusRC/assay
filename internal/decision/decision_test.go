package decision

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func keys(items []Item) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.Key
	}
	return out
}

func TestDisabledIsNoOp(t *testing.T) {
	items := []Item{{Key: "a", Text: "x"}, {Key: "b", Text: "y"}}
	got := Rank(context.Background(), Config{Enabled: false}, []string{"php"}, items)
	if len(got) != 2 || got[0].Key != "a" {
		t.Fatalf("disabled must preserve order, got %v", keys(got))
	}
}

func TestDeterministicRanksByTechOverlap(t *testing.T) {
	items := []Item{
		{Key: "iis", Text: "iis-tilde windows IIS asp"},
		{Key: "wp", Text: "wordpress-xmlrpc wordpress php"},
		{Key: "generic", Text: "missing-security-headers"},
	}
	cfg := Config{Enabled: true} // no APIKey -> deterministic
	got := Rank(context.Background(), cfg, []string{"wordpress", "php"}, items)
	if got[0].Key != "wp" {
		t.Fatalf("expected wordpress template first, got %v", keys(got))
	}
}

func TestTopNCaps(t *testing.T) {
	items := []Item{
		{Key: "wp", Text: "wordpress php"},
		{Key: "iis", Text: "iis asp"},
		{Key: "x", Text: "nothing"},
	}
	cfg := Config{Enabled: true, TopN: 1}
	got := Rank(context.Background(), cfg, []string{"wordpress"}, items)
	if len(got) != 1 || got[0].Key != "wp" {
		t.Fatalf("TopN=1 should keep only the most relevant, got %v", keys(got))
	}
}

func TestJevBackendRanksAndFallsBack(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		var req jevRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		ans := map[string]jevAnswer{}
		// q0 relevant, q1 not
		for k := range req.Questions {
			if k == "q0" {
				ans[k] = jevAnswer{Probability: 0.95}
			} else {
				ans[k] = jevAnswer{Probability: 0.05}
			}
		}
		_ = json.NewEncoder(w).Encode(jevResponse{Answers: ans})
	}))
	defer srv.Close()

	cfg := Config{Enabled: true, Model: defaultModel, BaseURL: srv.URL, APIKey: "secret"}
	items := []Item{{Key: "first", Text: "t0"}, {Key: "second", Text: "t1"}}
	got := Rank(context.Background(), cfg, []string{"nginx"}, items)
	if got[0].Key != "first" {
		t.Fatalf("Jev prob should order 'first' ahead, got %v", keys(got))
	}
	if gotPath != "/v1/evaluate" {
		t.Fatalf("wrong endpoint: %s", gotPath)
	}
	if gotAuth != "Bearer secret" {
		t.Fatalf("wrong auth header: %s", gotAuth)
	}
}

func TestJevErrorFallsBackToDeterministic(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cfg := Config{Enabled: true, Model: defaultModel, BaseURL: srv.URL, APIKey: "k"}
	items := []Item{{Key: "wp", Text: "wordpress php"}, {Key: "x", Text: "nothing"}}
	got := Rank(context.Background(), cfg, []string{"wordpress"}, items)
	if got[0].Key != "wp" {
		t.Fatalf("on gateway error must fall back to deterministic, got %v", keys(got))
	}
}

func TestLocalEngineKeylessOmitsAuth(t *testing.T) {
	var gotAuth string
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, sawAuth = r.Header["Authorization"]
		var req jevRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		ans := map[string]jevAnswer{}
		for k := range req.Questions {
			ans[k] = jevAnswer{Probability: 0.5}
		}
		_ = json.NewEncoder(w).Encode(jevResponse{Answers: ans})
	}))
	defer srv.Close()

	// local self-hosted engine, no key -> jev path is used, no Authorization header
	cfg := Config{Enabled: true, Model: defaultModel, BaseURL: srv.URL, APIKey: ""}
	got := Rank(context.Background(), cfg, []string{"nginx"}, []Item{{Key: "a", Text: "t"}})
	if len(got) != 1 {
		t.Fatalf("expected 1 item, got %d", len(got))
	}
	if sawAuth || gotAuth != "" {
		t.Fatalf("keyless local engine must send no Authorization header, got %q", gotAuth)
	}
}

func TestFromEnvLocalBaseEnablesKeyless(t *testing.T) {
	t.Setenv("AI_GATEWAY_API_KEY", "")
	t.Setenv("ASSAY_DECISION_API_KEY", "")
	t.Setenv("ASSAY_DECIDE", "")
	t.Setenv("ASSAY_DECISION_BASE_URL", "http://127.0.0.1:3000")
	c := FromEnv()
	if !c.Enabled || c.APIKey != "" || c.BaseURL != "http://127.0.0.1:3000" {
		t.Fatalf("local base must enable keyless: %+v", c)
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("ASSAY_DECISION_BASE_URL", "")
	t.Setenv("AI_GATEWAY_API_KEY", "")
	t.Setenv("ASSAY_DECISION_API_KEY", "")
	t.Setenv("ASSAY_DECIDE", "")
	if FromEnv().Enabled {
		t.Fatal("should be disabled with no env")
	}
	t.Setenv("AI_GATEWAY_API_KEY", "k")
	t.Setenv("ASSAY_DECIDE_TOP", "5")
	c := FromEnv()
	if !c.Enabled || c.TopN != 5 || c.APIKey != "k" || c.Model != defaultModel {
		t.Fatalf("unexpected config: %+v", c)
	}
}
