package openapisemantic

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	assayhttp "github.com/TyrusRC/assay/internal/http"
)

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
func (d *Detector) sendJSON(ctx context.Context, target, method string, body map[string]interface{}) (*assayhttp.Response, error) {
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
	f.Top10 = []string{"A06:2025"}
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
func responsesDiffer(a, b *assayhttp.Response) bool {
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
