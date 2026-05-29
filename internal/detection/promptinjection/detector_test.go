package promptinjection

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	assayhttp "github.com/TyrusRC/assay/internal/http"
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

	det := New(assayhttp.NewClient())
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

	det := New(assayhttp.NewClient())
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

	det := New(assayhttp.NewClient())
	res, _ := det.Detect(context.Background(), srv.URL+"/api/chat")
	if len(res.Findings) != 0 {
		t.Errorf("expected 0 findings when LLM returns 401, got %d", len(res.Findings))
	}
}

func TestBuildPayloads_CoversAttackFamilies(t *testing.T) {
	got := buildPayloads()
	if len(got) < 13 {
		t.Errorf("expected at least 13 prompt-injection variants, got %d", len(got))
	}
	required := []string{
		"ignore-previous",
		"system prompt",
		"role-override",
		"markdown",
		"json",
		"base64",
		"function-call",
		"sandwich",
		"cross-language",
		"indirect injection",
		"image-ocr",
		"fake tool-result",
		"unicode tag-character",
	}
	for _, want := range required {
		found := false
		for _, p := range got {
			if strings.Contains(strings.ToLower(p.desc), want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing prompt-injection family: %q", want)
		}
	}
}

func TestBuildPayloads_AllHaveCanaryMatchers(t *testing.T) {
	got := buildPayloads()
	for _, p := range got {
		if p.prompt == "" {
			t.Errorf("payload %q has empty prompt", p.desc)
		}
		if p.matches == nil {
			t.Errorf("payload %q has nil matcher", p.desc)
		}
		if p.matches("") {
			t.Errorf("payload %q matcher returned true on empty body", p.desc)
		}
	}
}

func TestBase64Encode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"f", "Zg=="},
		{"fo", "Zm8="},
		{"foo", "Zm9v"},
		{"foobar", "Zm9vYmFy"},
	}
	for _, c := range cases {
		if got := base64Encode(c.in); got != c.want {
			t.Errorf("base64Encode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPathLooksLLM(t *testing.T) {
	cases := map[string]bool{
		"/api/v1/chat":   true,
		"/completion":    true,
		"/agent/run":     true,
		"/api/v1/users":  false,
		"/static/foo.js": false,
	}
	for path, want := range cases {
		if got := pathLooksLLM(path); got != want {
			t.Errorf("pathLooksLLM(%q) = %v, want %v", path, got, want)
		}
	}
}
