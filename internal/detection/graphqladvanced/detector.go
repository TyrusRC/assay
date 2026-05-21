package graphqladvanced

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	scanhttp "github.com/TyrusRC/assay/internal/http"
)

// Detector probes a GraphQL endpoint for field-suggestion recovery,
// APQ bypass, and mutation-over-GET CSRF.
type Detector struct {
	client  *scanhttp.Client
	verbose bool
}

// New constructs a Detector. Nil client makes Detect a no-op.
func New(client *scanhttp.Client) *Detector {
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// Name returns the detector identifier.
func (d *Detector) Name() string { return "graphqladvanced" }

// Description returns a one-line summary.
func (d *Detector) Description() string {
	return "Probes a GraphQL endpoint for field-suggestion schema recovery, APQ (Automatic Persisted Queries) bypass, and mutation-over-GET CSRF — gaps the standard graphql/ detector does not cover."
}

// DetectOptions configures the probe.
type DetectOptions struct {
	// CandidateFields seeds the field-suggestion recovery loop. Empty
	// uses a small built-in list of typo'd common field names.
	CandidateFields []string
	// Timeout per request.
	Timeout time.Duration
}

// DefaultOptions returns recommended defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout: 10 * time.Second,
		CandidateFields: []string{
			"secretFiel", "secretField",
			"userAdmi", "isAdmi", "adminTok",
			"creditCar", "ssn", "passwor",
			"internalNot", "auditLo",
		},
	}
}

// DetectionResult carries findings and the list of techniques that
// triggered.
type DetectionResult struct {
	Vulnerable bool
	Findings   []*core.Finding
	Techniques []string
}

// Detect runs the three probes against target. Each probe is
// independent — a failure or timeout in one does not abort the others.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{
		Findings:   make([]*core.Finding, 0),
		Techniques: make([]string, 0),
	}
	if d == nil || d.client == nil {
		return res, nil
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultOptions().Timeout
	}
	if len(opts.CandidateFields) == 0 {
		opts.CandidateFields = DefaultOptions().CandidateFields
	}

	if !d.looksLikeGraphQL(ctx, target, opts) {
		return res, nil
	}

	if leaked := d.probeFieldSuggestions(ctx, target, opts); len(leaked) > 0 {
		res.Techniques = append(res.Techniques, "field_suggestion_recovery")
		res.Findings = append(res.Findings, buildSuggestionFinding(target, leaked))
	}

	if d.probeAPQBypass(ctx, target, opts) {
		res.Techniques = append(res.Techniques, "apq_bypass")
		res.Findings = append(res.Findings, buildAPQFinding(target))
	}

	if d.probeGETMutation(ctx, target, opts) {
		res.Techniques = append(res.Techniques, "get_mutation_csrf")
		res.Findings = append(res.Findings, buildGETMutationFinding(target))
	}

	res.Vulnerable = len(res.Findings) > 0
	return res, nil
}

// looksLikeGraphQL sends a trivial POST with a malformed query and
// checks whether the response shape is a GraphQL error envelope. This
// is the cheapest gate that protects non-GraphQL endpoints from
// pointless probing.
func (d *Detector) looksLikeGraphQL(ctx context.Context, target string, opts DetectOptions) bool {
	resp, err := d.postJSON(ctx, target, `{"query":"{ __typename }"}`, opts.Timeout)
	if err != nil || resp == nil {
		return false
	}
	body := resp.Body
	if !strings.Contains(strings.ToLower(resp.ContentType), "json") {
		return false
	}
	// Acceptable signals: a "data" or "errors" key at the top level.
	return strings.Contains(body, `"data"`) || strings.Contains(body, `"errors"`)
}

// probeFieldSuggestions issues queries with typo'd field names and
// scrapes "Did you mean ..." suggestions from the response. Returns
// the list of real field names recovered. Non-empty result means the
// server leaks schema despite introspection being disabled.
var suggestionRe = regexp.MustCompile(`(?i)did you mean[^a-zA-Z_]+([a-zA-Z_][a-zA-Z0-9_]*)`)

func (d *Detector) probeFieldSuggestions(ctx context.Context, target string, opts DetectOptions) []string {
	leaked := make([]string, 0)
	seen := make(map[string]bool)
	for _, candidate := range opts.CandidateFields {
		query := fmt.Sprintf(`{"query":"{ %s }"}`, candidate)
		resp, err := d.postJSON(ctx, target, query, opts.Timeout)
		if err != nil || resp == nil {
			continue
		}
		matches := suggestionRe.FindStringSubmatch(resp.Body)
		if len(matches) < 2 {
			continue
		}
		name := matches[1]
		// Ignore self-suggestions and obviously generic names.
		if name == candidate || seen[name] {
			continue
		}
		seen[name] = true
		leaked = append(leaked, name)
	}
	return leaked
}

// probeAPQBypass sends a payload that includes both a fake APQ
// extension hash and a normal "query" string. A correctly-configured
// APQ server refuses execution and returns PersistedQueryNotFound; a
// misconfigured one happily runs the query, breaking the allowlist
// guarantee APQ is meant to provide.
func (d *Detector) probeAPQBypass(ctx context.Context, target string, opts DetectOptions) bool {
	const probeQuery = "{ __typename }"
	hash := sha256.Sum256([]byte(probeQuery + "::probe"))
	payload := fmt.Sprintf(
		`{"query":"%s","extensions":{"persistedQuery":{"version":1,"sha256Hash":"%s"}}}`,
		probeQuery, hex.EncodeToString(hash[:]),
	)
	resp, err := d.postJSON(ctx, target, payload, opts.Timeout)
	if err != nil || resp == nil {
		return false
	}
	body := resp.Body
	if strings.Contains(body, "PersistedQueryNotFound") ||
		strings.Contains(body, "PERSISTED_QUERY_NOT_FOUND") {
		return false
	}
	// Look for an actual data response — the misconfig signal.
	return strings.Contains(body, `"data"`) &&
		strings.Contains(body, `"__typename"`)
}

// probeGETMutation crafts a mutation as a query-string parameter and
// fires it via GET. Servers that respond with a non-error JSON envelope
// turned mutations into CSRF gadgets.
func (d *Detector) probeGETMutation(ctx context.Context, target string, opts DetectOptions) bool {
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	q := u.Query()
	q.Set("query", "mutation { __typename }")
	u.RawQuery = q.Encode()

	reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	resp, err := d.client.Get(reqCtx, u.String())
	if err != nil || resp == nil {
		return false
	}
	if resp.StatusCode >= 400 {
		return false
	}
	body := resp.Body
	if strings.Contains(body, `"errors"`) && !strings.Contains(body, `"data"`) {
		return false
	}
	// A genuine "data" envelope on GET means the server executed the
	// mutation. That is the CSRF condition.
	return strings.Contains(body, `"data"`)
}

// postJSON wraps client.Do for the common GraphQL request shape.
func (d *Detector) postJSON(ctx context.Context, target, body string, timeout time.Duration) (*scanhttp.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.client.Do(reqCtx, &scanhttp.Request{
		Method:      "POST",
		URL:         target,
		Body:        body,
		ContentType: "application/json",
	})
}

func buildSuggestionFinding(target string, leaked []string) *core.Finding {
	f := core.NewFinding("GraphQL field suggestion exposes schema", core.SeverityMedium)
	f.Title = "Field suggestion leaks schema despite introspection lockdown"
	f.URL = target
	f.Tool = "graphqladvanced-detector"
	f.Description = "The GraphQL endpoint returns \"Did you mean ...?\" suggestions in response to typo'd field names. An attacker can iteratively reconstruct the schema field-by-field even when introspection is disabled, defeating the whole point of locking introspection down. Recovered field names: " + strings.Join(leaked, ", ") + "."
	f.Evidence = "leaked fields: " + strings.Join(leaked, ", ")
	f.Remediation = "Disable field suggestions in production. In Apollo, set the validation rule to strip 'didYouMean' from validation errors. In graphql-js, use a custom formatError to remove suggestion text."
	f.WithOWASPMapping(
		[]string{"WSTG-INFO-08"},
		[]string{"A05:2025"},
		[]string{"CWE-200"},
	)
	return f
}

func buildAPQFinding(target string) *core.Finding {
	f := core.NewFinding("GraphQL Automatic Persisted Query bypass", core.SeverityHigh)
	f.Title = "APQ allowlist bypassed via fallback execution"
	f.URL = target
	f.Tool = "graphqladvanced-detector"
	f.Description = "The endpoint accepted a request that combined an APQ extension with an unknown SHA-256 hash and a literal query string, executing the query rather than refusing on a cache miss. APQ is meant to restrict execution to the set of pre-registered hashes; a fallback path that runs arbitrary queries breaks that guarantee, neutralizing APQ as a security control."
	f.Evidence = "server returned a data envelope for an unknown APQ hash with an attached query string"
	f.Remediation = "Configure APQ in strict mode: when a hash is not registered, refuse with PersistedQueryNotFound and never execute the supplied query string. Apollo Server: persistedQueries: { cache, ttl, allowedOperations }. Verify the server is not in 'eager' fallback mode."
	f.WithOWASPMapping(
		[]string{"WSTG-ATHZ-04"},
		[]string{"A01:2025"},
		[]string{"CWE-862"},
	)
	return f
}

func buildGETMutationFinding(target string) *core.Finding {
	f := core.NewFinding("GraphQL mutation accepted over GET (CSRF)", core.SeverityHigh)
	f.Title = "GraphQL endpoint executes mutations over HTTP GET"
	f.URL = target
	f.Tool = "graphqladvanced-detector"
	f.Description = "The endpoint executed a mutation supplied as a query-string parameter of an HTTP GET request. GET-readable mutations are reachable cross-origin from <img>, <link>, <script>, and pre-flightless fetch with credentials, making every mutation a CSRF gadget on a user's session."
	f.Evidence = "GET /?query=mutation+{+__typename+} returned a data envelope"
	f.Remediation = "Restrict mutations to HTTP POST with application/json. Reject GET requests carrying a 'mutation' query string. Apollo: enable strict CSRF prevention (csrfPrevention: true)."
	f.WithOWASPMapping(
		[]string{"WSTG-SESS-05"},
		[]string{"A01:2025"},
		[]string{"CWE-352"},
	)
	return f
}

// Marshal helper kept for future expansion (e.g., richer APQ payload).
var _ = json.Marshal
