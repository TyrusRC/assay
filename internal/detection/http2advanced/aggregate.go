package http2advanced

import "context"

// DetectAll runs each probe in sequence and aggregates the findings.
// Errors are swallowed per-probe (each probe already swallows network
// failures) so DetectAll never returns a non-nil error today; the
// signature reserves the right to.
func (d *Detector) DetectAll(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	all := &DetectionResult{DetectionType: "all"}

	if r, err := d.DetectSettingsFlood(ctx, opts); err == nil && r != nil {
		all.Findings = append(all.Findings, r.Findings...)
	}
	if r, err := d.DetectHPACKPollution(ctx, opts); err == nil && r != nil {
		all.Findings = append(all.Findings, r.Findings...)
	}
	if r, err := d.DetectFlowControlExhaustion(ctx, opts); err == nil && r != nil {
		all.Findings = append(all.Findings, r.Findings...)
	}

	all.Vulnerable = len(all.Findings) > 0
	return all, nil
}
