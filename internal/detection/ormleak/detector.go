// Package ormleak detects ORM-driven over-fetch on JSON list/detail
// endpoints (the "Hibernate / Sequelize / Mongoose include=*" class of
// bug). Frameworks that honor caller-controlled `?include=` /
// `?expand=` / `?fields=` / `?with=` query parameters often reach into
// adjacent tables (or sibling models) without re-running the
// authorisation check the original endpoint enforces, leaking PII or
// credential material from related rows.
//
// The probe sends a baseline request, then re-sends with each known
// expansion-style parameter set to a wildcard or sensitive sibling
// value. A response that materially grows AND surfaces sensitive
// keys it didn't have before is the signal.
package ormleak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// expansionParams is the curated set of expansion-style query
// parameter names. Each value is paired with one or more wildcard /
// sibling-model expansion strings to try.
var expansionParams = []struct {
	name   string
	values []string
}{
	{"include", []string{"*", "all", "password,secret,token", "credentials"}},
	{"expand", []string{"*", "all", "secrets,credentials,roles"}},
	{"fields", []string{"*", "password,secret,token,api_key"}},
	{"with", []string{"*", "credentials,secrets"}},
	{"populate", []string{"*", "password,secret"}},
	{"select", []string{"*", "password,secret,token"}},
	{"$expand", []string{"*"}}, // OData
}

// sensitiveKeyRe matches JSON keys whose presence in the expanded
// response is highly suspicious. This is intentionally narrower than
// dataexposure's pattern set — we want to claim "expansion leaked
// new credentials" not "this response has an email field".
var sensitiveKeyRe = regexp.MustCompile(`(?i)(password|passwd|api[_-]?key|secret|token|hash|private[_-]?key|credential)`)

// Detector probes targetURL for ORM expansion leaks.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector wired to the project's shared HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries findings emitted by Detect.
type Result struct {
	Findings []*core.Finding
}

// Detect fetches a baseline of targetURL, then re-fetches with each
// expansion-style parameter set to a wildcard / sensitive value. A
// finding emits when the expanded response (a) is JSON, (b) is at
// least 25% longer than baseline, AND (c) contains a sensitive key
// that the baseline did not. The 25% size guard alone would catch
// pagination changes; the "new sensitive key" requirement narrows
// to the actual leak.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}

	baseResp, err := d.client.Get(ctx, targetURL)
	if err != nil || baseResp == nil {
		return res, nil
	}
	if !looksJSON(baseResp.ContentType, baseResp.Body) {
		return res, nil
	}
	baseSensitive := collectSensitiveKeys(baseResp.Body)

	for _, exp := range expansionParams {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		for _, value := range exp.values {
			probe := *u
			q := probe.Query()
			q.Set(exp.name, value)
			probe.RawQuery = q.Encode()
			probeURL := probe.String()

			resp, err := d.client.Get(ctx, probeURL)
			if err != nil || resp == nil {
				continue
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				continue
			}
			if !looksJSON(resp.ContentType, resp.Body) {
				continue
			}

			// Body must grow meaningfully.
			if len(resp.Body) < (5*len(baseResp.Body))/4 {
				continue
			}

			expandedSensitive := collectSensitiveKeys(resp.Body)
			newKeys := diff(expandedSensitive, baseSensitive)
			if len(newKeys) == 0 {
				continue
			}

			res.Findings = append(res.Findings, buildFinding(targetURL, exp.name, value, newKeys, resp))
			break // one finding per expansion parameter is enough
		}
	}
	return res, nil
}

// collectSensitiveKeys returns the set of sensitive-shaped keys that
// appear in the JSON body. We walk the parsed tree rather than
// regex-scanning raw bytes so a key embedded inside an unrelated
// string value doesn't false-positive.
func collectSensitiveKeys(body string) map[string]struct{} {
	out := map[string]struct{}{}
	var v interface{}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return out
	}
	walk(v, out)
	return out
}

func walk(v interface{}, out map[string]struct{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if sensitiveKeyRe.MatchString(k) {
				out[strings.ToLower(k)] = struct{}{}
			}
			walk(val, out)
		}
	case []interface{}:
		for _, item := range t {
			walk(item, out)
		}
	}
}

// diff returns the keys present in a but absent in b.
func diff(a, b map[string]struct{}) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}

// looksJSON is the same heuristic dataexposure uses.
func looksJSON(contentType, body string) bool {
	if strings.Contains(strings.ToLower(contentType), "json") {
		return true
	}
	t := strings.TrimLeft(body, " \t\r\n\xef\xbb\xbf")
	if t == "" {
		return false
	}
	return t[0] == '{' || t[0] == '['
}

func buildFinding(target, paramName, value string, newKeys []string, resp *skwshttp.Response) *core.Finding {
	finding := core.NewFinding("ORM Over-Fetch via Expansion Parameter", core.SeverityHigh)
	finding.URL = target
	finding.Parameter = paramName
	finding.Tool = "ormleak"
	finding.Confidence = core.ConfidenceHigh
	finding.Description = fmt.Sprintf(
		"Setting %s=%s caused the JSON response to surface previously-hidden sensitive fields (%s). The endpoint honours caller-controlled relation expansion without re-running the authorisation that the documented response shape relies on.",
		paramName, value, strings.Join(newKeys, ", "),
	)
	finding.Evidence = fmt.Sprintf("Expansion param: %s=%s\nNew sensitive keys exposed: %s\nResponse length: %d",
		paramName, value, strings.Join(newKeys, ", "), len(resp.Body))
	finding.Remediation = "Pin the JSON serializer's field set server-side (allow-list, not deny-list). Reject `include` / `expand` / `fields` query parameters that name unknown relations or sensitive scalars. Apply the same authorisation check to expanded relations as to the parent resource."
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A01:2025"},
		[]string{"CWE-200"},
	)
	finding.APITop10 = []string{"API3:2023"}
	return finding
}
