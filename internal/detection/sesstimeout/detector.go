// Package sesstimeout detects missing session timeout (WSTG-SESS-07).
package sesstimeout

import (
	"context"
	"fmt"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

type Detector struct {
	client *http.Client
}

func New(client *http.Client) *Detector { return &Detector{client: client} }

// Detect sends an authenticated request, waits, then resends to check
// if the session is still valid. A session that survives a short idle
// period is not necessarily misconfigured — this is a low-confidence probe.
func (d *Detector) Detect(ctx context.Context, targetURL string, wait time.Duration) ([]*core.Finding, error) {
	if wait <= 0 {
		wait = 5 * time.Second
	}

	first, err := d.client.Get(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("first request: %w", err)
	}
	if first.StatusCode == 401 || first.StatusCode == 403 {
		return nil, nil // no auth — nothing to test
	}

	select {
	case <-time.After(wait):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	second, err := d.client.Get(ctx, targetURL)
	if err != nil {
		return nil, fmt.Errorf("second request: %w", err)
	}

	if second.StatusCode == first.StatusCode && second.ContentLength > 0 {
		f := core.NewFinding("Session Does Not Expire", core.SeverityLow).At(targetURL, "")
		f.Description = fmt.Sprintf("Session still valid after %s idle. Verify that session timeout is configured.", wait)
		f.Confidence = core.ConfidenceLow
		f.Tool = "sesstimeout-detector"
		f.Remediation = "Configure an appropriate session idle timeout (15-30 minutes for sensitive apps)."
		f.WithOWASPMapping([]string{"WSTG-SESS-07"}, []string{"A07:2025"}, []string{"CWE-613"})
		return []*core.Finding{f}, nil
	}

	return nil, nil
}
