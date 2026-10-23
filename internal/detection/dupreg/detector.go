// Package dupreg tests for duplicate user registration (WSTG-IDNT-02).
package dupreg

import (
	"context"
	"fmt"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
)

type Detector struct {
	client *http.Client
}

func New(client *http.Client) *Detector { return &Detector{client: client} }

// Detect submits a registration twice with the same email. If the
// second attempt succeeds without error, the app allows duplicate
// registration.
func (d *Detector) Detect(ctx context.Context, registrationURL string) ([]*core.Finding, error) {
	if registrationURL == "" {
		return nil, nil
	}

	email := "assay_dupreg_test@test.local"
	body := fmt.Sprintf("username=assay_dupreg&email=%s&password=TestPass123!&password_confirm=TestPass123!", email)
	ct := "application/x-www-form-urlencoded"

	first, err := d.client.SendRawBody(ctx, registrationURL, "POST", body, ct)
	if err != nil {
		return nil, err
	}
	if first.StatusCode >= 400 {
		return nil, nil // registration endpoint not accepting POST
	}

	second, err := d.client.SendRawBody(ctx, registrationURL, "POST", body, ct)
	if err != nil {
		return nil, err
	}

	bodyLower := strings.ToLower(second.Body)
	duplicate := strings.Contains(bodyLower, "already exists") ||
		strings.Contains(bodyLower, "already registered") ||
		strings.Contains(bodyLower, "duplicate") ||
		strings.Contains(bodyLower, "already taken") ||
		second.StatusCode == 409 || second.StatusCode == 422

	if !duplicate && (second.StatusCode == 200 || second.StatusCode == 201 || second.StatusCode == 302) {
		f := core.NewFinding("Duplicate User Registration", core.SeverityMedium).At(registrationURL, "email")
		f.Description = fmt.Sprintf("Server accepted duplicate registration for %s without error. May allow account squatting or enumeration.", email)
		f.Evidence = fmt.Sprintf("Second registration with same email → HTTP %d", second.StatusCode)
		f.Confidence = core.ConfidenceMedium
		f.Tool = "dupreg-detector"
		f.Remediation = "Check for existing accounts before creating new ones. Return a clear error on duplicate registration."
		f.WithOWASPMapping([]string{"WSTG-IDNT-02"}, []string{"A07:2025"}, []string{"CWE-287"})
		return []*core.Finding{f}, nil
	}

	return nil, nil
}
