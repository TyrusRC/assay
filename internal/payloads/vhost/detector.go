package vhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Detector rotates Host: through a hostname wordlist against the
// target's IP, looking for response-body differentials that indicate
// the host is served from a distinct vhost block (an internal /
// staging / admin site sharing an IP with the public one).
//
// Mirrors AWVS VirtualHost_Audit.script.
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
	Timeout      time.Duration
	MaxBodyBytes int64
	// MaxVHosts caps the wordlist size to keep request count predictable.
	// 0 means "no cap"; the default wordlist is ~1000 entries.
	MaxVHosts int
	// MaxFindings caps the number of distinct vhosts reported per scan
	// (callers often want a handful, not the entire matching set).
	MaxFindings int
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() DetectOptions {
	return DetectOptions{
		Timeout:      10 * time.Second,
		MaxBodyBytes: 32 << 10,
		MaxVHosts:    150, // bounded to keep the scan cheap
		MaxFindings:  10,
	}
}

// DetectionResult mirrors the scanner convention.
type DetectionResult struct {
	URL         string
	BaselineSig string
	FoundHosts  []string
	Findings    []*core.Finding
	Vulnerable  bool
}

// Detect issues a baseline GET, then iterates the vhost wordlist
// against the same target with rotating Host: headers, comparing
// response signatures.
func (d *Detector) Detect(ctx context.Context, target string, opts DetectOptions) (*DetectionResult, error) {
	if opts.Timeout <= 0 {
		opts = DefaultOptions()
	}
	if opts.MaxBodyBytes <= 0 {
		opts.MaxBodyBytes = 32 << 10
	}
	if opts.MaxFindings <= 0 {
		opts.MaxFindings = 10
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("vhost: parse URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("vhost: URL has no host: %q", target)
	}

	baselineSig, err := d.fetchSignature(ctx, target, host, opts)
	if err != nil {
		return nil, fmt.Errorf("vhost: baseline: %w", err)
	}

	candidates := GenerateVHosts(rootDomain(host))
	if opts.MaxVHosts > 0 && len(candidates) > opts.MaxVHosts {
		candidates = candidates[:opts.MaxVHosts]
	}

	result := &DetectionResult{URL: target, BaselineSig: baselineSig}
	seen := map[string]bool{baselineSig: true}

	for _, vh := range candidates {
		if err := ctx.Err(); err != nil {
			return result, nil
		}
		if vh == host {
			continue
		}
		sig, err := d.fetchSignature(ctx, target, vh, opts)
		if err != nil {
			continue
		}
		if sig == "" || seen[sig] {
			continue
		}
		seen[sig] = true
		result.FoundHosts = append(result.FoundHosts, vh)
		result.Findings = append(result.Findings, d.toFinding(target, vh, sig))
		if len(result.Findings) >= opts.MaxFindings {
			break
		}
	}
	result.Vulnerable = len(result.Findings) > 0
	return result, nil
}

// fetchSignature retrieves the response and returns a stable signature
// (status code + content-length + first 16 KiB body hash) so distinct
// vhost blocks can be compared without false positives from minor
// per-request variation (timestamps, csrf tokens).
func (d *Detector) fetchSignature(ctx context.Context, target, hostHeader string, opts DetectOptions) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Host = hostHeader
	req.Header.Set("Host", hostHeader)
	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
	h := sha256.Sum256(body)
	return fmt.Sprintf("%d:%d:%s", resp.StatusCode, len(body), hex.EncodeToString(h[:8])), nil
}

func (d *Detector) toFinding(target, vhost, sig string) *core.Finding {
	f := core.NewFinding("virtualhost_disclosure", core.SeverityLow)
	f.Tool = "vhost"
	f.URL = target
	f.Title = "Virtual host disclosure: " + vhost
	f.Confidence = core.ConfidenceMedium
	f.Description = "A request with Host: " + vhost + " returned a distinct response signature from the public host. " +
		"An internal, staging, or admin site is co-located on the same IP and reachable by anyone who knows the hostname. " +
		"These sites typically receive less hardening than the public one and often expose dev tooling, debug endpoints, or stale credentials."
	f.Evidence = "signature " + sig
	f.Metadata["vhost"] = vhost
	f.Metadata["response_signature"] = sig
	f.Remediation = "Either decommission the alternate vhost or require authentication / VPN at the load balancer for any name not matching the public service."
	f.References = []string{"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information"}
	f = f.WithOWASPMapping(
		[]string{"WSTG-CONF-04"},
		[]string{"A05:2021"},
		[]string{"CWE-200"},
	)
	return f
}

func rootDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return host
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}
