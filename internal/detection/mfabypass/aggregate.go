package mfabypass

import (
	"context"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectAll runs the four MFA-bypass checks in sequence and aggregates
// the results. Errors from individual checks are returned alongside any
// partial findings already gathered.
func (d *Detector) DetectAll(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	aggregate := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: detectionAll,
	}
	var firstErr error
	add := func(res *DetectionResult, err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if res != nil {
			aggregate.Findings = append(aggregate.Findings, res.Findings...)
			if res.Vulnerable {
				aggregate.Vulnerable = true
			}
		}
	}

	if opts.LoginURL != "" && opts.ProtectedURL != "" {
		r, err := d.DetectMFAStepSkip(ctx, opts)
		add(r, err)
	}
	if opts.LoginURL != "" && opts.MFASubmitURL != "" {
		r, err := d.DetectMFANullValue(ctx, opts)
		add(r, err)
	}
	if opts.LoginURL != "" && opts.MFASubmitURL != "" {
		r, err := d.DetectMFABruteForce(ctx, opts)
		add(r, err)
	}
	if opts.LoginURL != "" && opts.MFASubmitURL != "" && opts.ProtectedURL != "" && opts.ResponseFlipPattern != "" {
		r, err := d.DetectMFAResponseManipulation(ctx, opts)
		add(r, err)
	}
	return aggregate, firstErr
}
