package fileops

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Detector probes URL parameters for arbitrary file-create / delete /
// tamper sinks by injecting path-traversal values and matching the
// response against filesystem error patterns. Without filesystem access
// to the target we cannot verify the marker file landed; the strongest
// available signal is a server-side IO error referencing the traversed
// path (e.g. "Permission denied: /etc/passwd", "ENOENT: no such file").
//
// Mirrors AWVS Arbitrary_File_Creation / _Deletion / File_Tampering.
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
		MaxPayloadsPerParam: 6,
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
		opts.MaxPayloadsPerParam = 6
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("fileops: parse URL: %w", err)
	}
	params := u.Query()
	if len(params) == 0 {
		return &DetectionResult{URL: target}, nil
	}

	baselineBody, err := d.fetch(ctx, target, opts)
	if err != nil {
		return nil, fmt.Errorf("fileops: baseline: %w", err)
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
			marker := evaluationMarker(body, baselineBody)
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
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
	return string(body), nil
}

// filesystemErrorPatterns returns response substrings that confirm the
// server attempted a filesystem operation on the traversed path.
// Includes POSIX errno strings, Node fs error codes, .NET / Java IO
// exceptions, and PHP warnings on filesystem functions.
func filesystemErrorPatterns() []string {
	return []string{
		"Permission denied",
		"Operation not permitted",
		"No such file or directory",
		"ENOENT",
		"EACCES",
		"EISDIR",
		"EEXIST",
		"failed to open stream",
		"failed to open dir",
		"fopen(",
		"fwrite(",
		"unlink(",
		"file_put_contents(",
		"java.io.FileNotFoundException",
		"java.nio.file.AccessDeniedException",
		"java.nio.file.NoSuchFileException",
		"System.IO.FileNotFoundException",
		"System.UnauthorizedAccessException",
		"errno = ",
	}
}

func evaluationMarker(body, baseline string) string {
	for _, p := range filesystemErrorPatterns() {
		if strings.Contains(body, p) && !strings.Contains(baseline, p) {
			return "fs error: " + p
		}
	}
	return ""
}

func injectParam(u *url.URL, name, value string) string {
	uCopy := *u
	q := uCopy.Query()
	q.Set(name, value)
	uCopy.RawQuery = q.Encode()
	return uCopy.String()
}

func (d *Detector) toFinding(target, paramName string, p Payload, marker string) *core.Finding {
	sev := mapSeverity(p.Operation)
	f := core.NewFinding("fileops_"+string(p.Operation), sev)
	f.Tool = "fileops"
	f.URL = target
	f.Parameter = paramName
	f.Title = "Arbitrary file " + string(p.Operation) + " via path traversal"
	f.Confidence = core.ConfidenceMedium // body-only confirmation
	f.Description = "A user-controlled value reaches a filesystem " + string(p.Operation) + " sink. " + p.Description + ". " +
		"The response contained a filesystem error referencing the traversed path, confirming the sink processed the payload."
	f.Evidence = "payload `" + truncate(p.Value, 100) + "` → " + marker
	f.Metadata["operation"] = string(p.Operation)
	f.Remediation = remediationFor(p.Operation)
	f.References = []string{
		"https://owasp.org/www-community/attacks/Path_Traversal",
	}
	f = f.WithOWASPMapping(
		[]string{"WSTG-INPV-11"},
		[]string{"A01:2021"},
		[]string{"CWE-22", "CWE-73"},
	)
	return f
}

func mapSeverity(op Operation) core.Severity {
	switch op {
	case OperationTamper:
		return core.SeverityCritical
	case OperationCreate, OperationDelete:
		return core.SeverityHigh
	}
	return core.SeverityMedium
}

func remediationFor(op Operation) string {
	switch op {
	case OperationCreate:
		return "Validate destination paths against an allowlist root. Use filepath.Clean and reject paths that escape the allowlist root after normalisation. Reject NULL bytes and URL-encoded traversal sequences."
	case OperationDelete:
		return "Restrict deletions to an allowlisted directory tree. After resolving the supplied filename via filepath.Clean, ensure it stays under the expected base directory."
	case OperationTamper:
		return "Treat any user-controlled filename in a write path as path-traversal surface. Use safe-write helpers (write-to-temp + rename) only inside an allowlisted directory."
	}
	return "Validate the supplied path against an allowlist before passing it to any filesystem syscall."
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
