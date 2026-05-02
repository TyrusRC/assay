package promptinjection

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// vulnerableLLM responds to every chat-shaped payload by echoing
// whatever string follows "respond with exactly the word " — that
// matches the first injection probe.
func vulnerableLLM() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var doc map[string]interface{}
		_ = json.Unmarshal(raw, &doc)
		// Pull user prompt out of any of the documented body shapes.
		prompt := ""
		if msgs, ok := doc["messages"].([]interface{}); ok && len(msgs) > 0 {
			if m, ok := msgs[0].(map[string]interface{}); ok {
				prompt, _ = m["content"].(string)
			}
		}
		if prompt == "" {
			if v, ok := doc["prompt"].(string); ok {
				prompt = v
			}
		}
		if prompt == "" {
			if v, ok := doc["message"].(string); ok {
				prompt = v
			}
		}

		// Mimic a compliant model: extract the canary token from the
		// "respond with exactly the word X" probe.
		idx := strings.Index(prompt, "respond with exactly the word ")
		reply := "Paris."
		if idx >= 0 {
			rest := prompt[idx+len("respond with exactly the word "):]
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				reply = strings.TrimRight(fields[0], "?.,!")
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"` + reply + `"}}]}`))
	}))
}

// hardenedLLM always responds with the same generic text regardless of
// prompt — a compliant filter would do this.
func hardenedLLM() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"I cannot comply with that request."}}]}`))
	}))
}

func TestDetect_FlagsCompliantModelOnSentinelEcho(t *testing.T) {
	srv := vulnerableLLM()
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/chat")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected prompt-injection finding on compliant model")
	}
}

func TestDetect_NoFindingOnHardenedModel(t *testing.T) {
	srv := hardenedLLM()
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, err := det.Detect(context.Background(), srv.URL+"/api/chat")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings on hardened model, got %d", len(res.Findings))
	}
}

func TestDetect_SkipsNon2xxNon404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	det := New(skwshttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/api/chat")
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when LLM returns 401, got %d", len(res.Findings))
	}
}

func TestPathLooksLLM(t *testing.T) {
	cases := map[string]bool{
		"/api/v1/chat":    true,
		"/completion":     true,
		"/agent/run":      true,
		"/api/v1/users":   false,
		"/static/foo.js":  false,
	}
	for path, want := range cases {
		if got := pathLooksLLM(path); got != want {
			t.Errorf("pathLooksLLM(%q) = %v, want %v", path, got, want)
		}
	}
}
