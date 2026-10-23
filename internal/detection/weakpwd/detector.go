// Package weakpwd probes for weak password policies (WSTG-ATHN-07).
package weakpwd

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

// Detect submits weak passwords to a registration or password-change
// endpoint. If the server accepts a trivially weak password, the policy
// is flagged.
func (d *Detector) Detect(ctx context.Context, registrationURL string) ([]*core.Finding, error) {
	if registrationURL == "" {
		return nil, nil
	}

	weakPasswords := []string{"a", "123", "password"}

	for _, weak := range weakPasswords {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		resp, err := d.client.SendRawBody(ctx, registrationURL, "POST",
			fmt.Sprintf("username=assay_weakpwd_test_%s&email=assay_%s@test.local&password=%s&password_confirm=%s",
				weak, weak, weak, weak),
			"application/x-www-form-urlencoded")
		if err != nil {
			continue
		}

		bodyLower := strings.ToLower(resp.Body)
		rejected := strings.Contains(bodyLower, "too short") ||
			strings.Contains(bodyLower, "too weak") ||
			strings.Contains(bodyLower, "password must") ||
			strings.Contains(bodyLower, "minimum") ||
			strings.Contains(bodyLower, "at least") ||
			strings.Contains(bodyLower, "requirements") ||
			resp.StatusCode == 422 || resp.StatusCode == 400

		if !rejected && (resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 302) {
			f := core.NewFinding("Weak Password Policy", core.SeverityMedium).At(registrationURL, "password")
			f.Description = fmt.Sprintf("Server accepted weak password %q without rejection. No minimum complexity or length enforcement detected.", weak)
			f.Evidence = fmt.Sprintf("Password %q → HTTP %d", weak, resp.StatusCode)
			f.Confidence = core.ConfidenceMedium
			f.Tool = "weakpwd-detector"
			f.Remediation = "Enforce minimum password length (8+), complexity rules, and reject common passwords."
			f.WithOWASPMapping([]string{"WSTG-ATHN-07"}, []string{"A07:2025"}, []string{"CWE-521"})
			return []*core.Finding{f}, nil
		}
	}

	return nil, nil
}
