package arginject

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/payloads/paraminject"
)

// Detector probes URL parameters for argument-injection by injecting
// flag-shaped payloads for each supported wrapped binary (curl, ssh,
// git, tar, find, convert, …) and matching the response against
// per-binary error fingerprints that confirm the flag was passed
// through to the binary's argv.
//
// Mirrors AWVS Argument_Injection.script.
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
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:             10 * time.Second,
		MaxBodyBytes:        128 << 10,
		MaxPayloadsPerParam: 8,
	}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL        string
	Findings   []*core.Finding
	Vulnerable bool
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
		return nil, fmt.Errorf("arginject: parse URL: %w", err)
	}
	params := u.Query()
	if len(params) == 0 {
		return &DetectionResult{URL: target}, nil
	}

	baselineBody, err := d.fetch(ctx, target, opts)
	if err != nil {
		return nil, fmt.Errorf("arginject: baseline: %w", err)
	}

	result := &DetectionResult{URL: target}
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

			injectedURL := injectParam(u, paramName, p.Value)
			body, err := d.fetch(ctx, injectedURL, opts)
			if err != nil {
				continue
			}
			marker := evaluationMarker(p, body, baselineBody)
			if marker == "" {
				continue
			}
			result.Findings = append(result.Findings, d.toFinding(target, paramName, p, marker))
			fired++
		}
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

func (d *Detector) fetch(ctx context.Context, target string, opts DetectOptions) (string, error) {
	rctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	body, _, err := paraminject.Fetch(rctx, d.client, target, opts.MaxBodyBytes)
	return body, err
}

// binaryErrorPatterns returns the per-binary error fingerprints that
// confirm the injected flag landed in the wrapper's argv.
func binaryErrorPatterns(binary string) []string {
	switch binary {
	case "curl":
		return []string{
			"curl: option",
			"curl: Failed",
			"curl: option --upload-file",
		}
	case "wget":
		return []string{"wget: missing URL", "wget: unrecognized option"}
	case "ssh", "scp":
		return []string{"ssh: connect to host", "Bad configuration option"}
	case "git":
		return []string{"fatal: ", "git: '", "Unable to read current working directory"}
	case "tar":
		return []string{"tar: ", "tar: Unrecognized archive"}
	case "find":
		return []string{"find: ", "find: invalid", "find: missing argument"}
	case "convert":
		return []string{"convert: ", "convert.im6", "MagickException"}
	case "mysql", "mysqldump":
		return []string{"mysqldump: Got error", "ERROR ", "Access denied"}
	case "python":
		return []string{"Traceback (most recent call last):", "SyntaxError:"}
	case "php":
		return []string{"PHP Fatal error: ", "PHP Parse error: "}
	case "ruby":
		return []string{"-e:", "ruby: "}
	case "perl":
		return []string{"perl: ", "syntax error at -e"}
	case "zip":
		return []string{"zip error:", "zip warning:"}
	case "rsync":
		return []string{"rsync: ", "rsync error:"}
	case "openssl":
		return []string{"unable to load config", "error loading", "139", "no objects found"}
	}
	return nil
}

func evaluationMarker(p Payload, body, baseline string) string {
	if hit := paraminject.FirstNewMatch(body, baseline, binaryErrorPatterns(p.Binary)); hit != "" {
		return p.Binary + " error pattern: " + hit
	}
	return ""
}

func injectParam(u *url.URL, name, value string) string {
	return paraminject.InjectParam(u, name, value)
}

func (d *Detector) toFinding(target, paramName string, p Payload, marker string) *core.Finding {
	sev := mapSeverity(p.Impact)
	f := core.NewFinding("argument_injection_"+string(p.Impact), sev)
	f.Tool = "arginject"
	f.URL = target
	f.Parameter = paramName
	f.Title = "Argument injection into " + p.Binary
	f.Confidence = core.ConfidenceHigh
	f.Description = "A user-controlled value reaches the argv of `" + p.Binary + "` without sanitisation. " + p.Description
	f.Evidence = "payload `" + paraminject.Truncate(p.Value, 100) + "` → " + marker
	f.Metadata["binary"] = p.Binary
	f.Metadata["impact"] = string(p.Impact)
	f.Remediation = "Strip leading `-` and `--` from values before passing to exec / Process.Start / spawn. " +
		"Prefer the argv-array form (curl `-o`-style args with explicit positional separation via `--`) over string-built command lines. " +
		"Where possible, replace the wrapped CLI with a library call."
	f.References = []string{
		"https://blog.sonarsource.com/argument-injection-vulnerabilities-in-popular-third-party-libraries/",
		"https://portswigger.net/research/argument-injection-vectors",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A03:2021"},
		[]string{"CWE-88"},
	)
	return f
}

func mapSeverity(i Impact) core.Severity {
	switch i {
	case ImpactRCE:
		return core.SeverityCritical
	case ImpactSSRF, ImpactFileWrite:
		return core.SeverityHigh
	case ImpactFileRead, ImpactConfigChange:
		return core.SeverityHigh
	case ImpactInfoLeak:
		return core.SeverityMedium
	default:
		return core.SeverityMedium
	}
}

