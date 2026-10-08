// Package deserialize detects insecure deserialization of untrusted data
// (Java / PHP / .NET ViewState / Python / Ruby) via two benign signals:
// serialized-object SHAPE in a client-controlled value, and deserialization
// ERROR strings triggered by a crafted (malformed, non-RCE) serialized blob.
// It never sends a gadget chain — reaching a deserializer is the finding.
package deserialize

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

const detectorTool = "deserialize"

// Detector performs insecure-deserialization detection.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New creates a new deserialization detector.
func New(client *http.Client) *Detector { return &Detector{client: client} }

// WithVerbose enables verbose output.
func (d *Detector) WithVerbose(v bool) *Detector { d.verbose = v; return d }

// DetectOptions configures detection behavior.
type DetectOptions struct {
	TestParams bool
	Params     []string
	Timeout    time.Duration
}

// DefaultOptions returns default detection options.
func DefaultOptions() DetectOptions {
	return DetectOptions{TestParams: true, Timeout: 10 * time.Second}
}

// DetectionResult contains deserialization detection results.
type DetectionResult struct {
	Vulnerable   bool
	Findings     []*core.Finding
	TestedParams []string
}

// deserErrorPatterns map a response signature to the serialization stack.
var deserErrorPatterns = map[string][]string{
	"Java": {
		"java.io.InvalidClassException", "java.io.StreamCorruptedException",
		"java.io.OptionalDataException", "java.lang.ClassNotFoundException",
		"invalid stream header", "ObjectInputStream", "cannot be cast",
	},
	"PHP": {
		"__PHP_Incomplete_Class", "unserialize()", "Error at offset",
		"Unexpected end of serialized data",
	},
	".NET": {
		"System.Runtime.Serialization", "BinaryFormatter", "SerializationException",
		"ViewStateException", "Invalid viewstate", "__viewstate",
	},
	"Python": {
		"_pickle.UnpicklingError", "UnpicklingError", "insecure string pickle",
		"pickle data was truncated", "could not find MARK",
	},
	"Ruby": {
		"Psych::", "Marshal.load", "marshal data too short", "dump format error",
	},
}

var phpSerialRe = regexp.MustCompile(`^(O:\d+:"|a:\d+:\{)`)

// serializedShape detects a serialized-object value by its magic prefix.
// Returns the stack name, or "" when the value does not look serialized.
func serializedShape(name, value string) string {
	v := strings.TrimSpace(value)
	lower := strings.ToLower(v)
	switch {
	case strings.HasPrefix(v, "rO0AB") || strings.HasPrefix(lower, "aced0005"):
		return "Java" // base64 of 0xACED0005, or the raw hex header
	case strings.EqualFold(name, "__VIEWSTATE"):
		return ".NET"
	case phpSerialRe.MatchString(v):
		return "PHP"
	case strings.HasPrefix(v, "BAh"): // Ruby Marshal 0x0408
		return "Ruby"
	case strings.HasPrefix(v, "gA") && len(v) > 8: // Python pickle proto 2+ (0x80 0x02)
		return "Python"
	}
	return ""
}

// errorProbes are malformed, NON-RCE serialized values. If the server tries to
// deserialize one, it emits a stack-specific error. None execute code.
var errorProbes = []string{
	"rO0ABXNyAAAAAAAAAAE=",     // corrupt Java ObjectStream header/body
	`O:255:"Assay\\NoClass":0:{}`, // PHP: class not found -> incomplete-class / offset error
	"gASVBQAAAAAAAACMA2JhZC4=", // malformed Python pickle (proto 2)
	"BAh7BjoGYUkiBmEGOgZFVA==", // malformed-ish Ruby Marshal
}

// matchDeserError returns the stack whose error pattern is in body but not in
// the baseline (a real delta), plus the matched pattern.
func matchDeserError(body, baseline string) (string, string) {
	lb := strings.ToLower(body)
	lbase := strings.ToLower(baseline)
	for stack, pats := range deserErrorPatterns {
		for _, p := range pats {
			lp := strings.ToLower(p)
			if strings.Contains(lb, lp) && !strings.Contains(lbase, lp) {
				return stack, p
			}
		}
	}
	return "", ""
}

func withParam(u *url.URL, key, val string) string {
	c := *u
	q := c.Query()
	q.Set(key, val)
	c.RawQuery = q.Encode()
	return c.String()
}

// Detect checks for insecure deserialization on a target's query parameters.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	result := &DetectionResult{Findings: []*core.Finding{}}
	u, err := url.Parse(target)
	if err != nil {
		return result, err
	}
	baseline, err := d.client.Get(ctx, target)
	if err != nil {
		return result, err
	}

	params := opts.Params
	if len(params) == 0 {
		for k := range u.Query() {
			params = append(params, k)
		}
	}
	for _, p := range params {
		result.TestedParams = append(result.TestedParams, p)
		// 1. Shape: an existing value already looks serialized -> deserialization surface.
		if stack := serializedShape(p, u.Query().Get(p)); stack != "" {
			result.Findings = append(result.Findings, d.finding(
				core.SeverityHigh, core.ConfidenceMedium, target, p,
				stack+" serialized object in a client-controlled parameter",
				"A client-supplied value in parameter "+p+" carries a "+stack+
					" serialized object. If the server deserializes it without an allowlist, "+
					"a gadget chain reaches an RCE sink.",
				"serialized-"+stack+" shape in "+p))
		}
		// 2. Error-based: a crafted serialized value triggers a deserialization error.
		for _, probe := range errorProbes {
			resp, err := d.client.Get(ctx, withParam(u, p, probe))
			if err != nil {
				continue
			}
			if stack, pat := matchDeserError(resp.Body, baseline.Body); stack != "" {
				result.Findings = append(result.Findings, d.finding(
					core.SeverityHigh, core.ConfidenceHigh, target, p,
					stack+" deserialization reachable via "+p,
					"A crafted serialized value in parameter "+p+" produced a "+stack+
						" deserialization error, so the server deserializes untrusted input there.",
					"error marker: "+pat))
				break
			}
		}
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

func (d *Detector) finding(sev core.Severity, conf core.Confidence,
	target, param, title, desc, ev string) *core.Finding {
	f := core.NewFinding("Insecure Deserialization", sev).At(target, param)
	f.Title = title
	f.Description = desc
	f.Evidence = ev
	f.Confidence = conf
	f.Tool = detectorTool
	f.Top10 = []string{"A08:2025"}
	f.APITop10 = []string{"API8:2023"}
	f.CWE = []string{"CWE-502"}
	f.WSTG = []string{"WSTG-INPV-11"}
	f.Remediation = "Do not deserialize untrusted data. Prefer a data-only format (JSON) with a " +
		"strict schema; sign and verify any serialized blob (HMAC); or enforce a deserialization " +
		"allowlist — Java ObjectInputFilter / Jackson no default typing, PHP unserialize " +
		"allowed_classes=false, .NET avoid BinaryFormatter and enable ViewState MAC, Python avoid " +
		"pickle on untrusted input, Ruby use safe_load for YAML."
	f.References = []string{
		"https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
		"https://cwe.mitre.org/data/definitions/502.html",
	}
	return f
}
