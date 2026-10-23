// Package fmtstr detects format-string injection (WSTG-INPV-13).
package fmtstr

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

type Detector struct {
	client  *http.Client
	verbose bool
}

func New(client *http.Client) *Detector { return &Detector{client: client} }
func (d *Detector) WithVerbose(v bool) *Detector { d.verbose = v; return d }

type DetectOptions struct {
	MaxPayloads int
}

type Result struct {
	Vulnerable bool
	Findings   []*core.Finding
}

var probes = []struct {
	payload  string
	markers  []string
	language string
}{
	{"%x%x%x%x", []string{"0", "a", "b", "c", "d", "e", "f"}, "C"},
	{"%s%s%s%s", nil, "C"},
	{"%p%p%p%p", []string{"0x", "(nil)"}, "C"},
	{"{0:x}{1:x}", nil, "Python"},
}

func (d *Detector) Detect(ctx context.Context, target, param, method string) (*Result, error) {
	result := &Result{Findings: make([]*core.Finding, 0)}

	baseline, err := d.client.SendPayload(ctx, target, param, "normalvalue", method)
	if err != nil {
		return result, fmt.Errorf("baseline: %w", err)
	}

	for _, p := range probes {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		resp, err := d.client.SendPayload(ctx, target, param, p.payload, method)
		if err != nil {
			continue
		}

		if resp.StatusCode == baseline.StatusCode && resp.Body == baseline.Body {
			continue
		}
		if strings.Contains(resp.Body, p.payload) {
			continue // echoed, not evaluated
		}

		// C-style: %x produces hex digits that weren't in baseline
		if len(p.markers) > 0 {
			for _, m := range p.markers {
				if strings.Contains(resp.Body, m) && !strings.Contains(baseline.Body, m) {
					result.Vulnerable = true
					f := core.NewFinding("Format String Injection", core.SeverityHigh).At(target, param)
					f.Description = fmt.Sprintf("Format-string injection in '%s' (%s): payload %q produced output containing %q absent from baseline",
						param, p.language, p.payload, m)
					f.Evidence = p.payload
					f.Tool = "fmtstr-detector"
					f.WithOWASPMapping([]string{"WSTG-INPV-13"}, []string{"A05:2025"}, []string{"CWE-134"})
					result.Findings = append(result.Findings, f)
					return result, nil
				}
			}
		}

		// %s crash detection: server error (500) when baseline was 200
		if p.markers == nil && resp.StatusCode >= 500 && baseline.StatusCode < 500 {
			result.Vulnerable = true
			f := core.NewFinding("Format String Injection", core.SeverityHigh).At(target, param)
			f.Description = fmt.Sprintf("Format-string injection in '%s' (%s): payload %q triggered %d (baseline %d)",
				param, p.language, p.payload, resp.StatusCode, baseline.StatusCode)
			f.Evidence = p.payload
			f.Tool = "fmtstr-detector"
			f.WithOWASPMapping([]string{"WSTG-INPV-13"}, []string{"A05:2025"}, []string{"CWE-134"})
			result.Findings = append(result.Findings, f)
			return result, nil
		}

		// Significant length change with no echo
		lenDelta := len(resp.Body) - len(baseline.Body)
		if lenDelta > 20 || lenDelta < -20 {
			result.Vulnerable = true
			f := core.NewFinding("Format String Injection", core.SeverityMedium).At(target, param)
			f.Description = fmt.Sprintf("Suspected format-string injection in '%s' (%s): payload %q changed response length by %d bytes",
				param, p.language, p.payload, lenDelta)
			f.Evidence = p.payload
			f.Confidence = core.ConfidenceMedium
			f.Tool = "fmtstr-detector"
			f.WithOWASPMapping([]string{"WSTG-INPV-13"}, []string{"A05:2025"}, []string{"CWE-134"})
			result.Findings = append(result.Findings, f)
			return result, nil
		}
	}

	return result, nil
}
