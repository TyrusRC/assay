package oauthflow

import (
	"context"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectAll runs every sub-check and aggregates the findings. Errors
// from individual probes are swallowed (with their findings dropped) so
// one broken endpoint doesn't mask others; the returned error reflects
// only context cancellation or setup-level failure.
func (d *Detector) DetectAll(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	combined := &DetectionResult{
		Findings:      make([]*core.Finding, 0),
		DetectionType: "all",
	}

	if opts.AuthzURL != "" {
		if r, err := d.DetectStateBinding(ctx, opts.AuthzURL, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
		}
		if opts.RegisteredRedirectURI != "" {
			if r, err := d.DetectRedirectURIMatching(ctx, opts.AuthzURL, opts); err == nil && r != nil {
				combined.Findings = append(combined.Findings, r.Findings...)
			}
		}
		if r, err := d.DetectResponseModeConfusion(ctx, opts.AuthzURL, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
		}
		if r, err := d.DetectImplicitFlow(ctx, opts.AuthzURL, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
		}
		if r, err := d.DetectNonceMissing(ctx, opts.AuthzURL, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
		}
		if opts.TokenURL != "" {
			if r, err := d.DetectPKCEDowngrade(ctx, opts.AuthzURL, opts.TokenURL, opts); err == nil && r != nil {
				combined.Findings = append(combined.Findings, r.Findings...)
			}
		}
		if r, err := d.DetectResourceIndicatorConfusion(ctx, opts.AuthzURL, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
		}
	}
	if opts.TokenURL != "" {
		if r, err := d.DetectIDTokenAlgNone(ctx, opts); err == nil && r != nil {
			combined.Findings = append(combined.Findings, r.Findings...)
		}
	}

	combined.Vulnerable = len(combined.Findings) > 0
	return combined, nil
}
