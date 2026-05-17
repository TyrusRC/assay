package openapisemantic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// detectorTool is the canonical Finding.Tool value emitted by this package.
const detectorTool = "openapisemantic-detector"

// Detector probes an OpenAPI-described service for semantic mismatches
// between the published schema and what the server actually enforces.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector bound to the supplied HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// Name returns the detector identifier used by the scanner registry.
func (d *Detector) Name() string { return "openapi-semantic" }

// Description returns a one-line summary of the detector.
func (d *Detector) Description() string {
	return "OpenAPI semantic exploits: type coercion, discriminator confusion, nullable leaks, additionalProperties bypass"
}

// DetectOptions selects the spec source and tunes request behavior.
// Exactly one of SpecJSON or SpecURL must be set.
type DetectOptions struct {
	// SpecJSON is a raw OpenAPI 3.x JSON body. Takes precedence over SpecURL.
	SpecJSON []byte
	// SpecURL is fetched via the bound client when SpecJSON is empty.
	SpecURL string
	// BaseURL overrides the server origin used to render path templates.
	// When empty, the detector uses SpecURL's origin (if any).
	BaseURL string
	// Timeout caps a single probe request. Zero defers to client default.
	Timeout time.Duration
}

// DetectionResult bundles the outcome of one probe family.
type DetectionResult struct {
	// Vulnerable is true when at least one finding was emitted.
	Vulnerable bool
	// Findings are the discovered issues (may be empty).
	Findings []*core.Finding
	// DetectionType identifies which probe family produced this result.
	DetectionType string
}

// DetectAll runs every probe family in this package and merges results.
// Each probe is independent; one failing does not short-circuit the rest.
func (d *Detector) DetectAll(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	merged := &DetectionResult{
		Findings:      []*core.Finding{},
		DetectionType: "openapi-semantic-all",
	}
	var firstErr error
	for _, probe := range []func(context.Context, DetectOptions) (*DetectionResult, error){
		d.DetectTypeCoercion,
		d.DetectDiscriminatorConfusion,
		d.DetectNullableLeak,
		d.DetectAdditionalPropertiesBypass,
	} {
		res, err := probe(ctx, opts)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if res == nil {
			continue
		}
		merged.Findings = append(merged.Findings, res.Findings...)
	}
	merged.Vulnerable = len(merged.Findings) > 0
	return merged, firstErr
}

// DetectTypeCoercion probes integer fields by sending the value as a quoted
// string. A 2xx response is the informational leg (Low); when the string
// payload carries an injection-shaped value and the response discriminably
// differs from a benign baseline, the finding is elevated to High.
func (d *Detector) DetectTypeCoercion(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{Findings: []*core.Finding{}, DetectionType: "type-coercion"}
	spec, base, err := d.load(ctx, opts)
	if err != nil {
		return result, err
	}
	for _, ref := range spec.Operations() {
		if ref.Method != "POST" && ref.Method != "PUT" && ref.Method != "PATCH" {
			continue
		}
		schema := ref.Op.JSONSchema()
		if schema == nil || schema.Type != "object" {
			continue
		}
		target := joinURL(base, ref.Path)
		for fieldName, prop := range schema.Properties {
			if prop == nil || prop.Type != "integer" {
				continue
			}
			// Step 1 — baseline with a valid integer.
			baseline, err := d.sendJSON(ctx, target, ref.Method, map[string]interface{}{fieldName: 1})
			if err != nil {
				continue
			}
			// Step 2 — same field, value as a quoted numeric string.
			coerced, err := d.sendJSON(ctx, target, ref.Method, map[string]interface{}{fieldName: "1"})
			if err != nil {
				continue
			}
			if !is2xx(coerced.StatusCode) {
				continue
			}
			// Step 3 — injection-shaped string payload.
			injBody := map[string]interface{}{fieldName: "1 OR 1=1"}
			injected, err := d.sendJSON(ctx, target, ref.Method, injBody)
			if err != nil {
				continue
			}
			if is2xx(injected.StatusCode) && responsesDiffer(baseline, injected) {
				f := newFinding(core.SeverityHigh, target, fieldName,
					fmt.Sprintf("OpenAPI %s.%s declared as integer; server accepted string payload %q and response differed from baseline.", ref.Path, fieldName, "1 OR 1=1"),
					fmt.Sprintf("baseline status=%d coerced status=%d injected status=%d", baseline.StatusCode, coerced.StatusCode, injected.StatusCode),
				)
				result.Findings = append(result.Findings, f)
				continue
			}
			// Coercion accepted but no discriminable processing — informational.
			f := newFinding(core.SeverityLow, target, fieldName,
				fmt.Sprintf("OpenAPI %s.%s declared as integer; server accepted quoted string value.", ref.Path, fieldName),
				fmt.Sprintf("baseline status=%d coerced status=%d", baseline.StatusCode, coerced.StatusCode),
			)
			result.Findings = append(result.Findings, f)
		}
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// DetectDiscriminatorConfusion probes oneOf/anyOf schemas with a
// discriminator. It sends the "safer" discriminator value (e.g. "user")
// together with fields that only the "privileged" branch (e.g. "admin")
// declares. Acceptance means the server treats the discriminator as a label
// rather than a gate — Critical.
func (d *Detector) DetectDiscriminatorConfusion(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{Findings: []*core.Finding{}, DetectionType: "discriminator-confusion"}
	spec, base, err := d.load(ctx, opts)
	if err != nil {
		return result, err
	}
	for _, ref := range spec.Operations() {
		if ref.Method != "POST" && ref.Method != "PUT" && ref.Method != "PATCH" {
			continue
		}
		schema := ref.Op.JSONSchema()
		if schema == nil {
			continue
		}
		branches, propName := collectDiscriminatorBranches(schema)
		if propName == "" || len(branches) < 2 {
			continue
		}
		safe, priv, privFields := chooseSafeAndPrivileged(branches)
		if safe == "" || priv == "" || len(privFields) == 0 {
			continue
		}
		body := map[string]interface{}{propName: safe}
		for _, f := range privFields {
			body[f] = privilegedValue(f)
		}
		target := joinURL(base, ref.Path)
		resp, err := d.sendJSON(ctx, target, ref.Method, body)
		if err != nil {
			continue
		}
		if !is2xx(resp.StatusCode) {
			continue
		}
		finding := newFinding(core.SeverityCritical, target, propName,
			fmt.Sprintf("Discriminator confusion: %s=%q was accepted alongside %s-only fields %v.", propName, safe, priv, privFields),
			fmt.Sprintf("status=%d body=%s", resp.StatusCode, truncate(resp.Body, 300)),
		)
		result.Findings = append(result.Findings, finding)
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// DetectNullableLeak probes nullable: true fields whose names look like
// credentials (password, token, secret). When the server accepts a null
// value on a creation endpoint, that's a Critical "no password" account.
func (d *Detector) DetectNullableLeak(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{Findings: []*core.Finding{}, DetectionType: "nullable-leak"}
	spec, base, err := d.load(ctx, opts)
	if err != nil {
		return result, err
	}
	for _, ref := range spec.Operations() {
		if ref.Method != "POST" && ref.Method != "PUT" && ref.Method != "PATCH" {
			continue
		}
		schema := ref.Op.JSONSchema()
		if schema == nil || schema.Type != "object" {
			continue
		}
		for fieldName, prop := range schema.Properties {
			if prop == nil || !prop.Nullable {
				continue
			}
			if !looksLikeCredential(fieldName) {
				continue
			}
			body := map[string]interface{}{fieldName: nil}
			// Populate sibling required fields with cheap dummies so the
			// request isn't rejected for unrelated reasons.
			for _, req := range schema.Required {
				if req == fieldName {
					continue
				}
				if _, ok := body[req]; ok {
					continue
				}
				if sub, ok := schema.Properties[req]; ok && sub != nil {
					body[req] = sampleForSchema(sub)
				} else {
					body[req] = "test"
				}
			}
			target := joinURL(base, ref.Path)
			resp, err := d.sendJSON(ctx, target, ref.Method, body)
			if err != nil {
				continue
			}
			if !is2xx(resp.StatusCode) {
				continue
			}
			finding := newFinding(core.SeverityCritical, target, fieldName,
				fmt.Sprintf("Nullable credential leak: %q is declared nullable and was accepted as null on %s.", fieldName, ref.Path),
				fmt.Sprintf("status=%d body=%s", resp.StatusCode, truncate(resp.Body, 300)),
			)
			result.Findings = append(result.Findings, finding)
		}
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// DetectAdditionalPropertiesBypass probes object schemas that explicitly
// disallow extras (`additionalProperties: false`). It sends a privileged
// extra (e.g. `isAdmin: true`); a 2xx response that echoes the field back
// is High — the schema's contract is being ignored.
func (d *Detector) DetectAdditionalPropertiesBypass(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{Findings: []*core.Finding{}, DetectionType: "additional-properties-bypass"}
	spec, base, err := d.load(ctx, opts)
	if err != nil {
		return result, err
	}
	extras := []string{"isAdmin", "role", "is_staff", "is_superuser"}
	for _, ref := range spec.Operations() {
		if ref.Method != "POST" && ref.Method != "PUT" && ref.Method != "PATCH" {
			continue
		}
		schema := ref.Op.JSONSchema()
		if schema == nil || schema.Type != "object" {
			continue
		}
		if schema.AdditionalProperties == nil || !schema.AdditionalProperties.Set {
			continue
		}
		if schema.AdditionalProperties.Allowed {
			continue
		}
		// Build a body with the declared required fields plus one extra.
		body := map[string]interface{}{}
		for _, req := range schema.Required {
			if sub, ok := schema.Properties[req]; ok && sub != nil {
				body[req] = sampleForSchema(sub)
			} else {
				body[req] = "test"
			}
		}
		extra := extras[0]
		body[extra] = true
		target := joinURL(base, ref.Path)
		resp, err := d.sendJSON(ctx, target, ref.Method, body)
		if err != nil {
			continue
		}
		if !is2xx(resp.StatusCode) {
			continue
		}
		if !responseEchoesField(resp.Body, extra) {
			continue
		}
		finding := newFinding(core.SeverityHigh, target, extra,
			fmt.Sprintf("additionalProperties: false on %s violated — extra field %q was accepted and reflected.", ref.Path, extra),
			fmt.Sprintf("status=%d body=%s", resp.StatusCode, truncate(resp.Body, 300)),
		)
		result.Findings = append(result.Findings, finding)
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// load resolves opts into (parsed spec, base URL) — exactly one of SpecJSON
// or SpecURL must be set, and BaseURL overrides SpecURL's origin when given.
func (d *Detector) load(ctx context.Context, opts DetectOptions) (*Spec, string, error) {
	var body []byte
	switch {
	case len(opts.SpecJSON) > 0:
		body = opts.SpecJSON
	case opts.SpecURL != "":
		if d.client == nil {
			return nil, "", fmt.Errorf("openapisemantic: nil client cannot fetch spec")
		}
		resp, err := d.client.Get(ctx, opts.SpecURL)
		if err != nil || resp == nil {
			return nil, "", fmt.Errorf("openapisemantic: fetch spec: %w", err)
		}
		if !is2xx(resp.StatusCode) {
			return nil, "", fmt.Errorf("openapisemantic: spec fetch returned status %d", resp.StatusCode)
		}
		body = []byte(resp.Body)
	default:
		return nil, "", fmt.Errorf("openapisemantic: SpecJSON or SpecURL required")
	}
	spec, err := ParseSpec(body)
	if err != nil {
		return nil, "", err
	}
	base := opts.BaseURL
	if base == "" && opts.SpecURL != "" {
		if u, err := url.Parse(opts.SpecURL); err == nil {
			u.Path = ""
			u.RawQuery = ""
			u.Fragment = ""
			base = u.String()
		}
	}
	if base == "" {
		return nil, "", fmt.Errorf("openapisemantic: BaseURL required when spec has no derivable origin")
	}
	return spec, base, nil
}

// sendJSON marshals body and POSTs / PUTs it as application/json. Any
// failure to marshal bubbles up as an error — encoding failures are bugs
// in the detector, not the target.
func (d *Detector) sendJSON(ctx context.Context, target, method string, body map[string]interface{}) (*skwshttp.Response, error) {
	if d.client == nil {
		return nil, fmt.Errorf("openapisemantic: nil client")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("openapisemantic: marshal body: %w", err)
	}
	return d.client.SendRawBody(ctx, target, method, string(raw), "application/json")
}

// newFinding centralizes the OWASP / metadata boilerplate so every probe
// emits a consistent Finding shape.
func newFinding(sev core.Severity, target, field, description, evidence string) *core.Finding {
	f := core.NewFinding("OpenAPI Semantic Bypass", sev)
	f.URL = target
	f.Parameter = field
	f.Description = description
	f.Evidence = evidence
	f.Tool = detectorTool
	f.Top10 = []string{"A04:2025"}
	f.APITop10 = []string{"API3:2023", "API6:2023"}
	f.CWE = []string{"CWE-20", "CWE-915"}
	f.Remediation = "Validate request bodies against the declared OpenAPI schema at runtime " +
		"(strict type checks, additionalProperties: false enforcement, discriminator gating). " +
		"Reject quoted-numeric values for integer fields, reject null for credential fields, " +
		"and bind only allow-listed properties into domain objects."
	return f
}

// joinURL stitches a base origin and a path template into an absolute URL.
// It is intentionally dumb: callers are expected to pre-substitute any
// {var} placeholders if the server actually requires concrete IDs.
func joinURL(base, path string) string {
	if base == "" {
		return path
	}
	b := strings.TrimRight(base, "/")
	p := "/" + strings.TrimLeft(path, "/")
	return b + p
}

// is2xx is the conventional 200..299 status check.
func is2xx(status int) bool { return status >= 200 && status < 300 }

// responsesDiffer reports whether two responses look discriminably
// different. We compare status code and (when statuses match) the trimmed
// body — that's the cheapest heuristic that still flags reflected SQL-y
// payloads in echo servers while ignoring incidental whitespace.
func responsesDiffer(a, b *skwshttp.Response) bool {
	if a == nil || b == nil {
		return false
	}
	if a.StatusCode != b.StatusCode {
		return true
	}
	return strings.TrimSpace(a.Body) != strings.TrimSpace(b.Body)
}

// truncate caps a string at n bytes for evidence inclusion.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// collectDiscriminatorBranches walks a schema's oneOf/anyOf and returns a
// (label -> required fields) map plus the discriminator property name.
// When a mapping is declared on the discriminator, labels are taken from
// it; otherwise we fall back to the enum on each branch's discriminator
// property.
func collectDiscriminatorBranches(s *Schema) (map[string][]string, string) {
	if s == nil || s.Discriminator == nil || s.Discriminator.PropertyName == "" {
		return nil, ""
	}
	propName := s.Discriminator.PropertyName
	variants := s.OneOf
	if len(variants) == 0 {
		variants = s.AnyOf
	}
	if len(variants) == 0 {
		return nil, ""
	}
	out := map[string][]string{}
	for _, v := range variants {
		if v == nil {
			continue
		}
		label := branchLabel(v, propName)
		if label == "" {
			continue
		}
		// Required fields minus the discriminator itself.
		fields := make([]string, 0, len(v.Required))
		for _, r := range v.Required {
			if r == propName {
				continue
			}
			fields = append(fields, r)
		}
		out[label] = fields
	}
	return out, propName
}

// branchLabel returns the discriminator value associated with one variant —
// either the enum on the discriminator property, or its declared example.
func branchLabel(v *Schema, propName string) string {
	if v == nil || v.Properties == nil {
		return ""
	}
	p, ok := v.Properties[propName]
	if !ok || p == nil {
		return ""
	}
	for _, e := range p.Enum {
		if s, ok := e.(string); ok {
			return s
		}
	}
	if s, ok := p.Example.(string); ok {
		return s
	}
	if s, ok := p.Default.(string); ok {
		return s
	}
	return ""
}

// chooseSafeAndPrivileged picks the "least privileged" label and one
// "privileged" label whose required fields are not in the safe branch.
// The returned privFields are the candidate admin-only properties.
func chooseSafeAndPrivileged(branches map[string][]string) (string, string, []string) {
	if len(branches) < 2 {
		return "", "", nil
	}
	// Prefer well-known labels when present, otherwise fall back to
	// any pair where one branch declares fields the other doesn't.
	prefSafe := []string{"user", "guest", "customer"}
	prefPriv := []string{"admin", "root", "superuser", "staff"}
	var safe, priv string
	for _, s := range prefSafe {
		if _, ok := branches[s]; ok {
			safe = s
			break
		}
	}
	for _, p := range prefPriv {
		if _, ok := branches[p]; ok {
			priv = p
			break
		}
	}
	if safe == "" || priv == "" {
		// Fallback: pick the smallest- and largest-field branches.
		var minLabel, maxLabel string
		minLen, maxLen := -1, -1
		for label, fields := range branches {
			if minLen < 0 || len(fields) < minLen {
				minLen = len(fields)
				minLabel = label
			}
			if len(fields) > maxLen {
				maxLen = len(fields)
				maxLabel = label
			}
		}
		if minLabel == maxLabel {
			return "", "", nil
		}
		safe = minLabel
		priv = maxLabel
	}
	safeSet := map[string]struct{}{}
	for _, f := range branches[safe] {
		safeSet[f] = struct{}{}
	}
	extras := []string{}
	for _, f := range branches[priv] {
		if _, ok := safeSet[f]; !ok {
			extras = append(extras, f)
		}
	}
	return safe, priv, extras
}

// privilegedValue returns a plausible value to slot into an admin-only
// field. Booleans get true; strings get "admin"; everything else gets 1.
func privilegedValue(field string) interface{} {
	lower := strings.ToLower(field)
	switch {
	case strings.HasPrefix(lower, "is_"), strings.HasPrefix(lower, "is"):
		return true
	case strings.Contains(lower, "role"), strings.Contains(lower, "permission"):
		return "admin"
	default:
		return true
	}
}

// looksLikeCredential matches a small allowlist of names where accepting
// null is unambiguously dangerous. Keeping this narrow avoids reporting
// every nullable string field in the spec.
func looksLikeCredential(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "password", "passwd", "pass", "secret", "token", "api_key", "apikey", "auth_token":
		return true
	}
	return false
}

// sampleForSchema returns a low-noise dummy value matching a schema's
// declared type — enough to satisfy "required" without tripping unrelated
// validators in the target.
func sampleForSchema(s *Schema) interface{} {
	if s == nil {
		return "test"
	}
	switch s.Type {
	case "integer", "number":
		return 1
	case "boolean":
		return true
	case "array":
		return []interface{}{}
	case "object":
		return map[string]interface{}{}
	default:
		return "test"
	}
}

// responseEchoesField returns true when the server appears to have
// persisted / reflected the named field — either by including it in a JSON
// response or by mentioning the name in a plain-text body. The check is
// deliberately permissive: the alternative (parsing every possible response
// shape) loses too many real findings.
func responseEchoesField(body, field string) bool {
	if body == "" || field == "" {
		return false
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err == nil {
		if _, ok := data[field]; ok {
			return true
		}
	}
	return strings.Contains(body, field)
}
