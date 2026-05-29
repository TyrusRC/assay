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

	if d.probeIncrementalDelivery(ctx, target, opts) {
		res.Techniques = append(res.Techniques, "defer_stream_enabled")
		res.Findings = append(res.Findings, buildIncrementalDeliveryFinding(target))
	}

	if sdl := d.probeFederationSDL(ctx, target, opts); sdl != "" {
		res.Techniques = append(res.Techniques, "apollo_federation_sdl_disclosure")
		res.Findings = append(res.Findings, buildFederationSDLFinding(target, sdl))
	}

	if d.probeFederationEntities(ctx, target, opts) {
		res.Techniques = append(res.Techniques, "apollo_federation_entities_exposed")
		res.Findings = append(res.Findings, buildFederationEntitiesFinding(target))
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

// probeIncrementalDelivery sends a query with the @defer directive on
// the __typename meta-field. Servers that accept incremental delivery
// return a multipart/mixed response or a JSON envelope with the
// `"hasNext":true` continuation marker. Enabled @defer/@stream opens a
// side-channel: even when the deferred field's value is denied, the
// chunk timing and presence reveal information about access-control
// boundaries (cardinality leaks via @stream, hidden-field presence via
// @defer's per-path error timing).
//
// References:
//   - https://github.com/graphql/graphql-spec/blob/main/rfcs/DeferStream.md
//   - PortSwigger 2024 "GraphQL incremental delivery side channels"
func (d *Detector) probeIncrementalDelivery(ctx context.Context, target string, opts DetectOptions) bool {
	// Use a defer fragment on __typename — every schema has it, and the
	// directive support is independent of whether any sensitive field
	// exists.
	q := `{"query":"query { __typename ... @defer { __typename } }"}`
	resp, err := d.postJSON(ctx, target, q, opts.Timeout)
	if err != nil || resp == nil {
		return false
	}

	// Multipart-mixed response is the canonical incremental delivery
	// transport.
	if strings.Contains(strings.ToLower(resp.ContentType), "multipart/mixed") {
		return true
	}
	body := resp.Body
	// JSON envelope variant — newer servers can also deliver incremental
	// payloads in a single multi-payload JSON object with hasNext / pending.
	if strings.Contains(body, `"hasNext":true`) || strings.Contains(body, `"hasNext": true`) {
		return true
	}
	if strings.Contains(body, `"incremental":[`) || strings.Contains(body, `"pending":[`) {
		return true
	}
	return false
}

// probeFederationSDL POSTs the Apollo Federation introspection query
// (_service { sdl }) and returns the disclosed SDL string when the
// server returns it. The _service field is a Federation-internal
// surface: it returns the FULL subgraph schema as a string, including
// every type, every field, every @key directive — i.e. every cardinal
// piece of information needed to plan an attack on the federation
// gateway. The query MUST be reachable only by the federation router,
// never by external clients.
//
// References:
//   - https://www.apollographql.com/docs/federation/subgraph-spec/#enhanced-introspection-with-query_service
//   - https://github.blog/2022-12-21-an-introduction-to-apollo-federation/
func (d *Detector) probeFederationSDL(ctx context.Context, target string, opts DetectOptions) string {
	q := `{"query":"query { _service { sdl } }"}`
	resp, err := d.postJSON(ctx, target, q, opts.Timeout)
	if err != nil || resp == nil || resp.StatusCode >= 400 {
		return ""
	}
	body := resp.Body
	// The SDL is returned inside a JSON envelope under data._service.sdl.
	// We don't need to fully parse JSON — the presence of an "sdl":"…"
	// field with substantial content is the signal.
	idx := strings.Index(body, `"sdl":"`)
	if idx < 0 {
		idx = strings.Index(body, `"sdl": "`)
	}
	if idx < 0 {
		return ""
	}
	// Snippet starting at the opening quote of the SDL value. A real
	// SDL is hundreds of bytes; an empty placeholder isn't worth flagging.
	snippet := body[idx:]
	if len(snippet) < 100 {
		return ""
	}
	if len(snippet) > 400 {
		snippet = snippet[:400] + "…"
	}
	return snippet
}

// probeFederationEntities POSTs an _entities query with a synthetic
// representation. A subgraph that responds successfully (even with a
// "type not found" error per the Apollo spec) confirms _entities is
// reachable — which means anyone who can hit the endpoint can request
// arbitrary entity types by their __typename + key fields, bypassing
// authorisation logic that the federation gateway would normally apply.
func (d *Detector) probeFederationEntities(ctx context.Context, target string, opts DetectOptions) bool {
	q := `{"query":"query($r:[_Any!]!){ _entities(representations:$r){ __typename } }","variables":{"r":[{"__typename":"User","id":"1"}]}}`
	resp, err := d.postJSON(ctx, target, q, opts.Timeout)
	if err != nil || resp == nil || resp.StatusCode >= 400 {
		return false
	}
	body := strings.ToLower(resp.Body)
	// Federation-aware servers reply with _entities-shaped responses
	// even when the requested type doesn't exist (the error names
	// _entities specifically).
	return strings.Contains(body, "_entities") ||
		strings.Contains(body, "no type found for") ||
		strings.Contains(body, "_any")
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

// buildIncrementalDeliveryFinding builds the finding for @defer/@stream
// being enabled. Severity is Medium — the feature itself is a side-
// channel risk, not an immediate vuln; a full audit would chain it with
// a deferred-field access-control bug to upgrade to High.
func buildIncrementalDeliveryFinding(target string) *core.Finding {
	f := core.NewFinding("GraphQL incremental delivery (@defer/@stream) enabled", core.SeverityMedium)
	f.Title = "GraphQL endpoint supports @defer/@stream incremental delivery"
	f.URL = target
	f.Tool = "graphqladvanced-detector"
	f.Description = "The endpoint accepted a query with the @defer directive. Incremental delivery emits the deferred portion as a separate chunk; even when the deferred field's value is denied, the chunk's PRESENCE and TIMING reveal information about access-control boundaries (cardinality of @stream'd lists, existence of @defer'd hidden fields). Combined with a per-field auth bug, this becomes a data-exfil side channel."
	f.Evidence = `query { __typename ... @defer { __typename } } returned multipart/mixed or {"hasNext":true}`
	f.Remediation = "Audit every @defer-eligible field for access-control checks that apply to the DEFERRED chunk too — not just the initial response. If the server is using graphql-js, consider disabling incremental delivery (`enableIncrementalDelivery: false`) until the access-control review is complete."
	f.References = []string{
		"https://github.com/graphql/graphql-spec/blob/main/rfcs/DeferStream.md",
		"https://portswigger.net/research/graphql-incremental-delivery-side-channels",
	}
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A01:2021"},
		[]string{"CWE-200"},
	)
	return f
}

// buildFederationSDLFinding builds the finding for Apollo Federation
// _service { sdl } being publicly reachable. High severity — full
// schema disclosure of a federation subgraph hands the attacker the
// data model.
func buildFederationSDLFinding(target, sdlSnippet string) *core.Finding {
	f := core.NewFinding("Apollo Federation _service { sdl } publicly reachable", core.SeverityHigh)
	f.Title = "GraphQL subgraph leaks Federation SDL via _service field"
	f.URL = target
	f.Tool = "graphqladvanced-detector"
	f.Description = "The endpoint responded to `query { _service { sdl } }` with a populated SDL string. " +
		"The Apollo Federation `_service` field is meant to be called only by the federation router; it returns the FULL subgraph schema as a single string, including every type, field, @key directive, and reference. " +
		"Public exposure hands an attacker the entire data model — including types and fields that introspection-disabled servers were supposed to hide."
	f.Evidence = "POST { _service { sdl } } returned SDL: " + sdlSnippet
	f.Remediation = "Restrict `_service` to the federation router only. Apollo Router and Apollo Gateway authenticate router-to-subgraph requests via a shared secret (APOLLO_ROUTER_SECRET / hard-coded HTTP header). Reject `_service` queries that don't carry this credential at the subgraph's HTTP layer (before GraphQL parsing)."
	f.References = []string{
		"https://www.apollographql.com/docs/federation/subgraph-spec/",
		"https://www.apollographql.com/docs/federation/subgraph-spec/#enhanced-introspection-with-query_service",
	}
	f.WithOWASPMapping(
		[]string{"WSTG-INFO-08"},
		[]string{"A05:2021"},
		[]string{"CWE-200"},
	)
	return f
}

// buildFederationEntitiesFinding builds the finding for _entities
// being reachable. High severity — bypasses gateway-level authorisation.
func buildFederationEntitiesFinding(target string) *core.Finding {
	f := core.NewFinding("Apollo Federation _entities resolver publicly reachable", core.SeverityHigh)
	f.Title = "GraphQL subgraph exposes _entities to external clients"
	f.URL = target
	f.Tool = "graphqladvanced-detector"
	f.Description = "The endpoint responded to a `_entities(representations: …)` query with a Federation-shaped response. " +
		"`_entities` is the router-side entity-fetch mechanism — it lets the caller specify `__typename` + key fields and the subgraph returns the corresponding entity. " +
		"When reachable externally, an attacker can request arbitrary entity types by their declared `@key` fields, bypassing any authorisation logic that the federation gateway would normally apply (rate limiting, field-level access control, query-cost limits)."
	f.Evidence = "POST { _entities(representations: [{__typename:\"User\",id:\"1\"}]) { __typename } } got Federation-shaped response"
	f.Remediation = "Block `_entities` (and `_service`) at the subgraph's HTTP layer for requests that don't authenticate as the federation router. The same shared-secret mechanism that protects `_service` should protect `_entities`."
	f.References = []string{
		"https://www.apollographql.com/docs/federation/subgraph-spec/",
	}
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A01:2021"},
		[]string{"CWE-863"},
	)
	return f
}

// Marshal helper kept for future expansion (e.g., richer APQ payload).
var _ = json.Marshal
