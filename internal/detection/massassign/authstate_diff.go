package massassign

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// AuthStateDiffOptions configures the two-phase mass-assignment probe
// that re-fetches a profile/state endpoint to confirm the privilege
// actually stuck.
type AuthStateDiffOptions struct {
	// WriteURL is the endpoint that accepts the (vulnerable) write —
	// typically a profile-update PATCH/PUT/POST.
	WriteURL string
	// WriteMethod is the HTTP method for the write. Defaults to PATCH.
	WriteMethod string
	// BaseBody is the JSON object the application normally accepts.
	// Privileged keys are added to this object before sending.
	BaseBody string
	// FetchURL is the endpoint that returns the user's current state /
	// profile. After the write, we re-fetch this URL to see whether the
	// privileged field was actually persisted. May be the same as
	// WriteURL when the write returns the updated record.
	FetchURL string
	// PrivilegedFields is the map of (field-name, escalation-value) we
	// inject. Defaults to a curated 12-entry set covering the common
	// auth/role/billing/verification flags. The detector emits one
	// finding per field that confirmed via re-fetch.
	PrivilegedFields map[string]interface{}
	// MaxFindings caps the number of confirmed findings emitted before
	// stopping. Defaults to 5.
	MaxFindings int
}

// DefaultAuthStateDiffOptions returns sane defaults: a curated set of
// privileged fields covering the role/admin/verification/billing axis.
// Callers typically only need to populate WriteURL + FetchURL + BaseBody.
func DefaultAuthStateDiffOptions() AuthStateDiffOptions {
	return AuthStateDiffOptions{
		WriteMethod: "PATCH",
		PrivilegedFields: map[string]interface{}{
			"isAdmin":      true,
			"is_admin":     true,
			"admin":        true,
			"role":         "admin",
			"roles":        []string{"admin"},
			"is_staff":     true,
			"is_superuser": true,
			"verified":     true,
			"is_verified":  true,
			"emailVerified": true,
			"email_verified": true,
			"premium":      true,
			"plan":         "enterprise",
		},
		MaxFindings: 5,
	}
}

// DetectWithReFetch is the bug-bounty-grade mass-assignment primitive: it
// adds a privileged field to a write request, then re-fetches a profile
// endpoint to check whether the field actually stuck on the server side.
//
// The existing single-request Detect emits findings on field-reflection
// alone — but field-reflection is noisy: many APIs echo arbitrary fields
// back without persisting them, and many APIs strip privileged fields
// during binding but include them in the response (e.g., a serializer
// ignores unknown fields when reading but includes the request as a
// debug artifact in the response). Both cases are FPs for the
// reflection-only detector. The re-fetch primitive eliminates that whole
// class of FPs by checking ground truth.
//
// Probe shape:
//
//   - Phase 0: fetch FetchURL to capture the user's current state. This
//     is the "before" snapshot — what the user looked like BEFORE we
//     attempted privilege escalation.
//   - Phase 1: for each privileged field in PrivilegedFields:
//   - Build a write body that adds the field to BaseBody.
//   - PUT/PATCH/POST the write to WriteURL.
//   - Re-fetch FetchURL.
//   - Compare: did the privileged field appear in the user's profile
//     where it wasn't before AND with an escalating value?
//   - Phase 2: emit one Critical finding per confirmed field.
//
// We deliberately do not flag on response-of-the-write — that's the same
// FP pattern the existing detector trips on. Only re-fetch confirms.
func (d *Detector) DetectWithReFetch(ctx context.Context, opts AuthStateDiffOptions) (*DetectionResult, error) {
	opts = applyAuthStateDefaults(opts)
	result := &DetectionResult{Findings: make([]*core.Finding, 0)}

	if opts.WriteURL == "" {
		return result, fmt.Errorf("WriteURL is required")
	}
	if opts.FetchURL == "" {
		return result, fmt.Errorf("FetchURL is required")
	}
	if opts.BaseBody == "" {
		return result, fmt.Errorf("BaseBody is required (the JSON object the app normally accepts)")
	}

	if err := ctx.Err(); err != nil {
		return result, err
	}

	// Phase 0: snapshot the "before" state.
	beforeResp, err := d.client.Get(ctx, opts.FetchURL)
	if err != nil {
		return result, fmt.Errorf("before-state fetch: %w", err)
	}
	if beforeResp.StatusCode < 200 || beforeResp.StatusCode >= 300 {
		// We can't establish the baseline state, so any "after" diff is
		// uninterpretable. Bail rather than emit FPs.
		return result, nil
	}
	beforeState, err := parseJSONObject(beforeResp.Body)
	if err != nil {
		// Profile endpoint returned non-JSON — can't do field-level diff.
		return result, nil
	}

	for fieldName, escalationValue := range opts.PrivilegedFields {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if len(result.Findings) >= opts.MaxFindings {
			break
		}
		result.TestedPayloads++

		// Build the write body: BaseBody with the privileged field added.
		body, err := injectField(opts.BaseBody, fieldName, escalationValue)
		if err != nil {
			continue
		}

		// Phase 1a: write.
		_, err = d.client.SendRawBody(ctx, opts.WriteURL, opts.WriteMethod, body, "application/json")
		if err != nil {
			continue
		}

		// Phase 1b: re-fetch.
		afterResp, err := d.client.Get(ctx, opts.FetchURL)
		if err != nil {
			continue
		}
		if afterResp.StatusCode < 200 || afterResp.StatusCode >= 300 {
			continue
		}
		afterState, err := parseJSONObject(afterResp.Body)
		if err != nil {
			continue
		}

		// Phase 2: did the privileged field stick?
		if !privilegeStuck(beforeState, afterState, fieldName) {
			continue
		}

		finding := d.buildAuthStateFinding(opts, fieldName, escalationValue, beforeState, afterState, afterResp.StatusCode)
		result.Findings = append(result.Findings, finding)
		result.Vulnerable = true
	}

	return result, nil
}

func (d *Detector) buildAuthStateFinding(opts AuthStateDiffOptions, fieldName string, escalationValue interface{}, before, after map[string]interface{}, afterStatus int) *core.Finding {
	finding := core.NewFinding(
		fmt.Sprintf("Mass Assignment: %q persisted via re-fetch confirmation", fieldName),
		core.SeverityCritical,
	)
	finding.URL = opts.WriteURL
	finding.Tool = "mass-assignment-detector"
	finding.Description = fmt.Sprintf(
		"A %s request to %s with an extra %q=%v field caused the field to appear in the subsequent %s GET on %s. The server bound a client-supplied privilege flag to the persisted user record — verified by re-fetching state, not by response echo.",
		opts.WriteMethod, opts.WriteURL, fieldName, escalationValue, "GET", opts.FetchURL,
	)
	beforeVal := "<absent>"
	if v, ok := before[fieldName]; ok {
		beforeVal = fmt.Sprintf("%v", v)
	}
	afterVal := "<absent>"
	if v, ok := after[fieldName]; ok {
		afterVal = fmt.Sprintf("%v", v)
	}
	finding.Evidence = strings.Join([]string{
		fmt.Sprintf("write URL:                 %s %s", opts.WriteMethod, opts.WriteURL),
		fmt.Sprintf("fetch URL:                 GET %s", opts.FetchURL),
		fmt.Sprintf("field:                     %s", fieldName),
		fmt.Sprintf("attempted value:           %v", escalationValue),
		fmt.Sprintf("state before write:        %s = %s", fieldName, beforeVal),
		fmt.Sprintf("state after write:         %s = %s", fieldName, afterVal),
		fmt.Sprintf("re-fetch status:           %d", afterStatus),
	}, "\n")
	finding.Remediation = "Use an explicit allowlist of writable fields when binding request bodies to model objects (the 'safe parameters' pattern in Rails, FluentValidation in .NET, Pydantic field-level constraints in FastAPI, GraphQL InputType allowlists). Never use blanket binders like ActiveRecord's update_attributes without strong_parameters, Mongoose Model.create({...req.body}) without filtering, or Spring @ModelAttribute on JPA entities. Treat any unknown field in a write request as a hard error — never as 'silently ignored'."
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-20"},
		[]string{"A04:2025", "A08:2025"},
		[]string{"CWE-915"},
	)
	finding.APITop10 = []string{"API3:2023", "API6:2023"}
	return finding
}

// privilegeStuck reports whether fieldName transitioned from absent (or
// non-escalating) in `before` to a present + escalating value in `after`.
//
// "Escalating" is conservative — bool true, role-string "admin"/"true",
// numeric > 0, []string containing "admin". Random unrelated additions
// (e.g., the API decided to include a "request_id" in the after-fetch
// that wasn't in the before-fetch) won't trip this check because they
// don't match the field name we're testing.
func privilegeStuck(before, after map[string]interface{}, fieldName string) bool {
	afterVal, afterHas := after[fieldName]
	if !afterHas {
		return false
	}
	if !isEscalationValue(afterVal) {
		return false
	}
	beforeVal, beforeHas := before[fieldName]
	if !beforeHas {
		return true
	}
	// Field existed before — only count as escalation if it transitioned
	// from non-escalating to escalating.
	return !isEscalationValue(beforeVal)
}

// injectField returns a JSON body equal to baseBody with fieldName added
// (or replaced) at the top level with the supplied value. Preserves the
// rest of the structure verbatim so detectors don't accidentally strip
// fields the application requires.
func injectField(baseBody, fieldName string, value interface{}) (string, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(baseBody), &obj); err != nil {
		return "", fmt.Errorf("baseBody is not a JSON object: %w", err)
	}
	obj[fieldName] = value
	out, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func parseJSONObject(s string) (map[string]interface{}, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(s), &obj); err != nil {
		return nil, err
	}
	return obj, nil
}

func applyAuthStateDefaults(opts AuthStateDiffOptions) AuthStateDiffOptions {
	def := DefaultAuthStateDiffOptions()
	if opts.WriteMethod == "" {
		opts.WriteMethod = def.WriteMethod
	}
	if len(opts.PrivilegedFields) == 0 {
		opts.PrivilegedFields = def.PrivilegedFields
	}
	if opts.MaxFindings <= 0 {
		opts.MaxFindings = def.MaxFindings
	}
	return opts
}
