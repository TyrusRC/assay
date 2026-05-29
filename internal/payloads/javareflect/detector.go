package javareflect

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/payloads/paraminject"
)

// Detector probes URL parameters for Java-reflection sinks by injecting
// reflection payloads and matching the response against the Java error
// fingerprint set (RuntimeException, NoSuchMethodException, etc.) or
// runtime-exposed framework banners (Tomcat, Spring4Shell pipeline).
//
// Mirrors AWVS Reflection.script.
type Detector struct {
	client  *http.Client
	verbose bool
}

// New constructs a Detector.
func New(client *http.Client) *Detector {
	if client == nil {
		client = http.DefaultClient
	}
	return &Detector{client: client}
}

// WithVerbose toggles diagnostic output.
func (d *Detector) WithVerbose(v bool) *Detector {
	d.verbose = v
	return d
}

// DetectOptions tunes the probe.
type DetectOptions struct {
	Timeout             time.Duration
	MaxBodyBytes        int64
	MaxPayloadsPerParam int
	// ConfirmedJavaOnly gates RCE-class payloads behind a confirmed
	// Java fingerprint in the baseline response.
	ConfirmedJavaOnly bool
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:             10 * time.Second,
		MaxBodyBytes:        128 << 10,
		MaxPayloadsPerParam: 8,
		ConfirmedJavaOnly:   true,
	}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL          string
	JavaDetected bool
	Findings     []*core.Finding
	Vulnerable   bool
}

// Detect runs the injection probe.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 128 << 10
	}
	if opts.MaxPayloadsPerParam <= 0 {
		opts.MaxPayloadsPerParam = 8
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("javareflect: parse URL: %w", err)
	}
	params := u.Query()
	if len(params) == 0 {
		return &DetectionResult{URL: target}, nil
	}

	baselineBody, baselineResp, err := d.fetch(ctx, target, opts)
	if err != nil {
		return nil, fmt.Errorf("javareflect: baseline: %w", err)
	}

	result := &DetectionResult{URL: target}
	if isJavaResponse(baselineResp, baselineBody) {
		result.JavaDetected = true
	}

	payloads := GetPayloads()
	seen := map[string]bool{}
	for paramName := range params {
		fired := 0
		for _, p := range payloads {
			if fired >= opts.MaxPayloadsPerParam {
				break
			}
			key := paramName + "|" + p.Value
			if seen[key] {
				continue
			}
			seen[key] = true

			if opts.ConfirmedJavaOnly && !result.JavaDetected && p.Impact == ImpactRCE {
				continue
			}

			injectedURL := injectParam(u, paramName, p.Value)
			body, _, err := d.fetch(ctx, injectedURL, opts)
			if err != nil {
				continue
			}
			marker := evaluationMarker(body, baselineBody)
			if marker == "" {
				continue
			}
			if !result.JavaDetected {
				result.JavaDetected = true
			}
			result.Findings = append(result.Findings, d.toFinding(target, paramName, p, marker, result.JavaDetected))
			fired++
		}
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

func (d *Detector) fetch(ctx context.Context, target string, opts DetectOptions) (string, *http.Response, error) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	return paraminject.Fetch(rctx, d.client, target, opts.MaxBodyBytes)
}

func isJavaResponse(resp *http.Response, body string) bool {
	if resp != nil {
		if v := resp.Header.Get("Server"); v != "" {
			lv := strings.ToLower(v)
			for _, k := range []string{"tomcat", "jetty", "wildfly", "glassfish", "jboss", "weblogic", "websphere", "coyote"} {
				if strings.Contains(lv, k) {
					return true
				}
			}
		}
		if v := resp.Header.Get("X-Powered-By"); v != "" {
			lv := strings.ToLower(v)
			if strings.Contains(lv, "servlet") || strings.Contains(lv, "jsp") || strings.Contains(lv, "java") {
				return true
			}
		}
		for _, c := range resp.Header.Values("Set-Cookie") {
			if strings.HasPrefix(strings.ToUpper(c), "JSESSIONID=") {
				return true
			}
		}
	}
	for _, p := range GetErrorPatterns() {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}

func evaluationMarker(body, baseline string) string {
	if hit := paraminject.FirstNewMatch(body, baseline, GetErrorPatterns()); hit != "" {
		return "error pattern: " + hit
	}
	return ""
}

func injectParam(u *url.URL, name, value string) string {
	return paraminject.InjectParam(u, name, value)
}

func (d *Detector) toFinding(target, paramName string, p Payload, marker string, javaConfirmed bool) *core.Finding {
	sev := mapSeverity(p.Impact)
	conf := core.ConfidenceMedium
	if javaConfirmed {
		conf = core.ConfidenceHigh
	}
	f := core.NewFinding("java_reflect_"+string(p.Impact), sev)
	f.Tool = "javareflect"
	f.URL = target
	f.Parameter = paramName
	f.Title = "Java reflection abuse: " + p.Technique
	f.Confidence = conf
	f.Description = "A user-controlled value reaches a Java reflection sink. " + p.Description
	f.Evidence = "payload `" + paraminject.Truncate(p.Value, 100) + "` → " + marker
	f.Metadata["technique"] = p.Technique
	f.Metadata["impact"] = string(p.Impact)
	f.Remediation = "Replace reflection on tainted strings with explicit, allowlisted dispatch. " +
		"For BeanUtils.populate-style binders, restrict allowed property names. " +
		"For JNDI lookups, set com.sun.jndi.ldap.object.trustURLCodebase=false (and the rmi/cosnaming equivalents)."
	f.References = []string{
		"https://github.com/frohoff/ysoserial",
		"https://portswigger.net/research/exploiting-spring-boot-actuators",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-INPV-11"},
		[]string{"A03:2021"},
		[]string{"CWE-470"},
	)
	return f
}

func mapSeverity(i Impact) core.Severity {
	switch i {
	case ImpactRCE:
		return core.SeverityCritical
	case ImpactSSRF:
		return core.SeverityHigh
	case ImpactInfoLeak:
		return core.SeverityMedium
	default:
		return core.SeverityMedium
	}
}

