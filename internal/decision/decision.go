// Package decision is assay's template-relevance decision engine — the "Jev for
// nuclei" pattern: given the target's detected tech, rank (and optionally cap)
// the template set so the scan spends effort where it is relevant.
//
// Two backends, best-first:
//
//  1. jev  — TypeSafe Jev via Vercel AI Gateway (POST /v1/evaluate), a calibrated
//     boolean "relevant?" per template in one round trip. Enabled when an
//     AI_GATEWAY_API_KEY is present.
//  2. deterministic — token overlap of each template's id/name/tags with the
//     detected-tech tokens. Always available, no key, no network.
//
// Ranking only reorders by default (TopN=0 keeps every template — no coverage
// loss). TopN>0 is an explicit operator cap (ASSAY_DECIDE_TOP) to cut the
// firehose, not a silent skip.
package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// jevClient is a dedicated HTTP client for Jev gateway calls, with explicit
// timeouts so we never depend on http.DefaultClient's zero-value behaviour.
var jevClient = &http.Client{Timeout: 90 * time.Second}

// maxJevResponseSize limits Jev response body reads to prevent OOM.
const maxJevResponseSize = 10 << 20 // 10 MB

const (
	defaultBaseURL = "https://ai-gateway.vercel.sh"
	defaultModel   = "typesafe-ai/jev"
)

// Item is one candidate to rank. Key identifies it; Text is the metadata the
// relevance decision reads (template id + name + tags).
type Item struct {
	Key  string
	Text string
}

// Config controls the decision engine. Zero value = disabled (no reorder).
type Config struct {
	Enabled bool
	TopN    int // >0 caps the result to the N most relevant (operator opt-in)
	Model   string
	BaseURL string
	APIKey  string
}

// FromEnv builds a Config from the environment. Enabled when ASSAY_DECIDE is
// truthy or an AI_GATEWAY_API_KEY is present.
func FromEnv() Config {
	key := strings.TrimSpace(os.Getenv("AI_GATEWAY_API_KEY"))
	if key == "" {
		key = strings.TrimSpace(os.Getenv("ASSAY_DECISION_API_KEY"))
	}
	baseEnv := strings.TrimSpace(os.Getenv("ASSAY_DECISION_BASE_URL"))
	// Enable on an explicit key, ASSAY_DECIDE, or a self-hosted local engine URL.
	enabled := truthy(os.Getenv("ASSAY_DECIDE")) || key != "" || isLocal(baseEnv)
	top := 0
	if v := strings.TrimSpace(os.Getenv("ASSAY_DECIDE_TOP")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			top = n
		}
	}
	model := strings.TrimSpace(os.Getenv("ASSAY_DECISION_MODEL"))
	if model == "" {
		model = defaultModel
	}
	base := baseEnv
	if base == "" {
		base = defaultBaseURL
	}
	return Config{Enabled: enabled, TopN: top, Model: model, BaseURL: base, APIKey: key}
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// isLocal reports whether a base URL points at a self-hosted loopback engine —
// which needs no key (the key authenticates a remote hosted gateway only).
func isLocal(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "127.0.0.1", "localhost", "0.0.0.0", "::1":
		return true
	}
	return false
}

// Rank orders items by relevance to the tech tokens (highest first) and returns
// the reordered slice. With no tokens or when the backend yields nothing, the
// original order is preserved (stable). TopN>0 caps the result.
func Rank(ctx context.Context, cfg Config, techTokens []string, items []Item) []Item {
	if !cfg.Enabled || len(items) == 0 {
		return items
	}
	scores := score(ctx, cfg, techTokens, items)
	idx := make([]int, len(items))
	for i := range items {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return scores[idx[a]] > scores[idx[b]] })
	out := make([]Item, 0, len(items))
	for _, i := range idx {
		out = append(out, items[i])
	}
	if cfg.TopN > 0 && cfg.TopN < len(out) {
		out = out[:cfg.TopN]
	}
	return out
}

// score returns a relevance score per item (same index as items). Jev when a key
// is set (falling back to deterministic on any error), else deterministic.
func score(ctx context.Context, cfg Config, techTokens []string, items []Item) []float64 {
	// Use the Jev HTTP engine when a hosted key is set OR a self-hosted local
	// engine is configured (keyless); fall back to deterministic on any error.
	if cfg.APIKey != "" || isLocal(cfg.BaseURL) {
		if s, err := jevScore(ctx, cfg, techTokens, items); err == nil {
			return s
		}
	}
	return deterministicScore(techTokens, items)
}

func deterministicScore(techTokens []string, items []Item) []float64 {
	toks := make([]string, 0, len(techTokens))
	for _, t := range techTokens {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			toks = append(toks, t)
		}
	}
	scores := make([]float64, len(items))
	for i, it := range items {
		text := strings.ToLower(it.Text)
		n := 0
		for _, t := range toks {
			if strings.Contains(text, t) {
				n++
			}
		}
		scores[i] = float64(n)
	}
	return scores
}

// --- Jev (TypeSafe via Vercel AI Gateway) ---

type jevQuestion struct {
	Type         string            `json:"type"`
	Instructions string            `json:"instructions"`
	Criteria     map[string]string `json:"criteria,omitempty"`
}

type jevRequest struct {
	Model string `json:"model"`
	// Domain routes a multi-adapter engine to the right per-domain adapter
	// (assay is a web DAST -> "web"); a single-adapter engine ignores it.
	Domain    string                 `json:"domain,omitempty"`
	State     string                 `json:"state"`
	Questions map[string]jevQuestion `json:"questions"`
}

type jevAnswer struct {
	// A pointer: the engine omits "probability" entirely on an error response
	// (oversized state, a malformed row, ...). A plain float64 would silently
	// decode that as 0.0 — "confirmed not a finding" — instead of "no opinion".
	Probability *float64 `json:"probability"`
}

type jevResponse struct {
	Answers map[string]jevAnswer `json:"answers"`
}

func jevScore(ctx context.Context, cfg Config, techTokens []string, items []Item) ([]float64, error) {
	state := "Target technologies: " + strings.Join(techTokens, ", ")
	qs := make(map[string]jevQuestion, len(items))
	keys := make([]string, len(items))
	for i, it := range items {
		qn := "q" + strconv.Itoa(i)
		keys[i] = qn
		qs[qn] = jevQuestion{
			Type:         "boolean",
			Instructions: "Is this security template relevant to run against the target? Template: " + it.Text,
		}
	}
	body, err := json.Marshal(jevRequest{Model: cfg.Model, Domain: "web", State: state, Questions: qs})
	if err != nil {
		return nil, err
	}
	reqCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		strings.TrimRight(cfg.BaseURL, "/")+"/v1/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if cfg.APIKey != "" { // hosted gateway authenticates; a local engine is keyless
		req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := jevClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{resp.StatusCode}
	}
	var out jevResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJevResponseSize)).Decode(&out); err != nil {
		return nil, err
	}
	scores := make([]float64, len(items))
	for i, qn := range keys {
		// Relevance ranking only (not a suppression signal): a missing probability
		// sorts last, which is the safe default for this use.
		if p := out.Answers[qn].Probability; p != nil {
			scores[i] = *p
		}
	}
	return scores, nil
}

// Adjudicate asks the engine, per finding, whether it is a real, reportable finding
// (not noise or a mere indicator), returning a probability in [0,1] per item at the
// same index, or nil at that index when the engine had no opinion for that one item
// (e.g. an oversized state rejected by the engine) — the caller MUST treat nil as
// "no opinion", never as 0.0, or a per-item error becomes a confident false "not a
// finding" that can wrongly deprioritize a real finding. FAIL-OPEN by contract: a
// disabled engine, no local/keyed backend, or any transport error returns (nil, err)
// and the caller MUST keep every finding unchanged — this never suppresses a
// candidate, it only scores one. Each Item.Text should carry the finding's verified
// evidence so the model adjudicates on proof, not a lead.
func Adjudicate(ctx context.Context, cfg Config, items []Item) ([]*float64, error) {
	if !cfg.Enabled || len(items) == 0 {
		return nil, nil
	}
	if cfg.APIKey == "" && !isLocal(cfg.BaseURL) {
		return nil, nil
	}
	// One round trip per finding: the evidence goes in `state` and the question +
	// true/false `criteria` are fixed — this matches how the model was trained
	// (observation in the state, not folded into the instruction), which the batched
	// form does not, and which otherwise degrades noise discrimination.
	//
	// Requests are fanned out with bounded concurrency. Individual failures set
	// that item to nil (no opinion) rather than aborting the entire batch.
	q := map[string]jevQuestion{"q": {
		Type:         "boolean",
		Instructions: "Is this a real, reportable security finding?",
		Criteria:     map[string]string{"true": "a real, exploitable vulnerability", "false": "noise / not reportable alone"},
	}}
	const maxParallel = 5
	scores := make([]*float64, len(items))
	errs := make([]error, len(items))
	sem := make(chan struct{}, maxParallel)
	var wg sync.WaitGroup
	for i, it := range items {
		wg.Add(1)
		go func(idx int, item Item) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			body, err := json.Marshal(jevRequest{Model: cfg.Model, Domain: "web", State: item.Text, Questions: q})
			if err != nil {
				errs[idx] = err
				return
			}
			reqCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
				strings.TrimRight(cfg.BaseURL, "/")+"/v1/evaluate", bytes.NewReader(body))
			if err != nil {
				errs[idx] = err
				return
			}
			if cfg.APIKey != "" {
				req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := jevClient.Do(req)
			if err != nil {
				errs[idx] = err
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				errs[idx] = &httpError{resp.StatusCode}
				return
			}
			var out jevResponse
			if err := json.NewDecoder(io.LimitReader(resp.Body, maxJevResponseSize)).Decode(&out); err != nil {
				errs[idx] = err
				return
			}
			scores[idx] = out.Answers["q"].Probability
		}(i, it)
	}
	wg.Wait()
	// If every request failed, report the first error so the caller can
	// fail-open on the whole batch. Partial success is returned as-is:
	// items with errors keep their nil score (no opinion).
	allFailed := true
	var firstErr error
	for _, e := range errs {
		if e == nil {
			allFailed = false
			break
		}
		if firstErr == nil {
			firstErr = e
		}
	}
	if allFailed && firstErr != nil {
		return nil, firstErr
	}
	return scores, nil
}

type httpError struct{ code int }


func (e *httpError) Error() string { return "decision gateway HTTP " + strconv.Itoa(e.code) }
