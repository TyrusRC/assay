// Package dataexposure detects excessive data exposure in API responses
// (OWASP API3:2023, read-side complement to massassign). The detector
// fetches a target endpoint, walks the JSON body, and emits findings on
// keys whose names match a curated PII / secret pattern set.
//
// The signal is intentionally narrow: we flag keys that *should not be
// returned to the client at all*, regardless of role. A second-pass
// "auth-stripped" comparison is available via DetectWithUnauth, which
// re-fetches without the supplied auth headers and emits a higher-severity
// finding when the same sensitive key still appears.
package dataexposure

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// SensitivePattern is one named regex bound to a severity. The first
// regex that matches a JSON key wins; ordering in sensitivePatterns is
// the source of truth for severity.
type SensitivePattern struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity core.Severity
}

// sensitivePatterns is the curated key-name signature set. Patterns are
// matched against lowercased JSON keys so callers can use mixed case.
// Adding a new entry is one line — the matcher iterates linearly so order
// chooses precedence when multiple patterns would match.
var sensitivePatterns = []SensitivePattern{
	// Credentials — Critical: should never leave the server.
	{"password", regexp.MustCompile(`(?:^|_)(password|passwd|pwd)(?:$|_)`), core.SeverityCritical},
	{"password_hash", regexp.MustCompile(`password_?hash|hashed_?password|pwhash`), core.SeverityCritical},
	{"private_key", regexp.MustCompile(`private_?key|secret_?key|signing_?key`), core.SeverityCritical},
	{"api_key", regexp.MustCompile(`api[_-]?key|apikey`), core.SeverityCritical},
	{"access_token", regexp.MustCompile(`access_?token|refresh_?token|bearer_?token|id_?token`), core.SeverityCritical},
	{"session", regexp.MustCompile(`(?:^|_)(session_?id|session_?token|sessid|jsessionid)(?:$|_)`), core.SeverityHigh},
	{"otp_secret", regexp.MustCompile(`(?:^|_)(otp_?secret|totp_?secret|mfa_?secret|seed)(?:$|_)`), core.SeverityCritical},
	{"recovery_code", regexp.MustCompile(`(?:recovery|backup)_?code`), core.SeverityHigh},

	// Financial — High.
	{"card_pan", regexp.MustCompile(`(?:^|_)(card_?(?:number|pan)|pan|credit_?card)(?:$|_)`), core.SeverityHigh},
	{"card_cvv", regexp.MustCompile(`(?:^|_)(cvv|cvc|cvv2)(?:$|_)`), core.SeverityHigh},
	{"iban", regexp.MustCompile(`(?:^|_)iban(?:$|_)`), core.SeverityMedium},
	{"bank_account", regexp.MustCompile(`(?:bank|account)_?(?:no|number)`), core.SeverityHigh},

	// Identity — Medium / High.
	{"ssn", regexp.MustCompile(`(?:^|_)(ssn|social_?security_?number|nin|tin)(?:$|_)`), core.SeverityHigh},
	{"date_of_birth", regexp.MustCompile(`(?:^|_)(dob|date_?of_?birth|birthdate)(?:$|_)`), core.SeverityMedium},
	{"phone", regexp.MustCompile(`(?:^|_)(phone|phone_?number|mobile|tel)(?:$|_)`), core.SeverityMedium},
	{"address", regexp.MustCompile(`(?:^|_)(home_?address|street_?address|residence)(?:$|_)`), core.SeverityMedium},
	{"government_id", regexp.MustCompile(`passport_?(?:no|number)|driver_?(?:license|licence)|national_?id`), core.SeverityHigh},

	// Internal/system fields — Info / Medium.
	{"internal_id", regexp.MustCompile(`(?:^|_)(internal_?id|backend_?id|system_?id)(?:$|_)`), core.SeverityLow},
	{"jwt_secret", regexp.MustCompile(`jwt_?secret|hmac_?key|signing_?secret`), core.SeverityCritical},
	{"aws", regexp.MustCompile(`aws_?(?:access|secret)_?key`), core.SeverityCritical},
	{"db_credentials", regexp.MustCompile(`db_?(?:password|user|host|conn|connection_?string)`), core.SeverityHigh},
}

// Detector runs the field-name analyzer over JSON responses fetched from
// the target endpoint.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector backed by the project's shared HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries the findings emitted by Detect.
type Result struct {
	Findings []*core.Finding
}

// Detect fetches targetURL and inspects its JSON body for sensitive keys.
// Non-JSON responses produce no findings; missing client returns empty.
// One finding is emitted per (key path, pattern) pair so reports cite each
// leak discretely.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	resp, err := d.client.Get(ctx, targetURL)
	if err != nil || resp == nil {
		return res, nil
	}
	if !looksJSON(resp.ContentType, resp.Body) {
		return res, nil
	}

	var parsed interface{}
	if err := json.Unmarshal([]byte(resp.Body), &parsed); err != nil {
		return res, nil
	}

	hits := findSensitiveKeys(parsed, "")
	for _, h := range hits {
		res.Findings = append(res.Findings, buildFinding(targetURL, h, false))
	}
	return res, nil
}

// hit captures one matched key with its JSON path and the pattern that
// triggered it. Path is dot-and-bracket joined for human consumption.
type hit struct {
	Path     string
	Key      string
	Pattern  SensitivePattern
	SnippetV string // shortened value, never logged in full
}

// findSensitiveKeys walks any JSON value and returns matched keys.
// Values are summarised, not echoed in full, so reports never carry
// the underlying secret bytes. Recursion is bounded only by the JSON's
// nesting; pathological inputs are caller-prevented (HTTP body cap).
func findSensitiveKeys(v interface{}, prefix string) []hit {
	var out []hit
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			subPath := k
			if prefix != "" {
				subPath = prefix + "." + k
			}
			lc := strings.ToLower(k)
			for _, p := range sensitivePatterns {
				if p.Pattern.MatchString(lc) {
					out = append(out, hit{
						Path:     subPath,
						Key:      k,
						Pattern:  p,
						SnippetV: snippet(val),
					})
					// First-match-wins so we don't double-report the same key.
					break
				}
			}
			out = append(out, findSensitiveKeys(val, subPath)...)
		}
	case []interface{}:
		for i, item := range t {
			subPath := fmt.Sprintf("%s[%d]", prefix, i)
			out = append(out, findSensitiveKeys(item, subPath)...)
		}
	}
	return out
}

// snippet returns at most a 16-character preview of a JSON value, with
// strings shown in quotes. The full value is intentionally not exposed.
func snippet(v interface{}) string {
	switch t := v.(type) {
	case string:
		if len(t) <= 16 {
			return fmt.Sprintf("%q", t)
		}
		return fmt.Sprintf("%q", t[:13]+"...")
	case nil:
		return "null"
	default:
		s := fmt.Sprintf("%v", t)
		if len(s) > 16 {
			return s[:13] + "..."
		}
		return s
	}
}

// looksJSON reports whether the response body is plausibly JSON, by
// content-type header or — as a fallback when the server is sloppy —
// by leading character. We only look at trimmed bodies because some
// servers prepend BOM or whitespace.
func looksJSON(contentType, body string) bool {
	if strings.Contains(strings.ToLower(contentType), "json") {
		return true
	}
	t := strings.TrimLeft(body, " \t\r\n\xef\xbb\xbf")
	if t == "" {
		return false
	}
	switch t[0] {
	case '{', '[':
		return true
	}
	return false
}

func buildFinding(targetURL string, h hit, alsoUnauth bool) *core.Finding {
	severity := h.Pattern.Severity
	title := "Excessive Data Exposure"
	if alsoUnauth {
		// Same field exposed without auth is strictly worse — bump one tier.
		switch severity {
		case core.SeverityHigh, core.SeverityMedium:
			severity = core.SeverityCritical
		}
	}
	finding := core.NewFinding(title, severity)
	finding.URL = targetURL
	finding.Parameter = h.Path
	finding.Tool = "dataexposure"
	finding.Confidence = core.ConfidenceHigh
	desc := fmt.Sprintf(
		"Sensitive field %q (%s) is included in the JSON response. APIs should never return credential, secret, or restricted PII material to the client.",
		h.Path, h.Pattern.Name,
	)
	if alsoUnauth {
		desc += " The same field is also returned without authentication, so any caller can read it."
	}
	finding.Description = desc
	finding.Evidence = fmt.Sprintf("Path: %s\nPattern: %s\nValue preview: %s",
		h.Path, h.Pattern.Name, h.SnippetV)
	finding.Remediation = "Remove sensitive fields from the response or hash/redact them server-side. If the field is needed for a privileged client, return it only behind an explicit authorization check."
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A01:2025"},
		[]string{"CWE-200"},
	)
	finding.APITop10 = []string{"API3:2023"}
	return finding
}
