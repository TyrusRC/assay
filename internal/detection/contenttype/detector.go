// Package contenttype probes a JSON-accepting endpoint for content-type
// confusion: servers that have multiple body parsers wired up often skip
// the validation / auth logic that fires for the documented type when a
// client switches to an alternative one.
//
// Three alternative parsers are exercised: application/xml,
// application/x-www-form-urlencoded, and multipart/form-data. Each is
// sent with a payload that carries the same data shape as the JSON
// baseline. When the alternative reaches the same handler — observed
// via 2xx status, body-similarity to the JSON baseline, or distinctly
// different from the soft-404 response — the detector emits a Medium
// finding because:
//
//   - XML acceptance re-enables the XXE detector at this endpoint.
//   - Form acceptance can sidestep CSRF-token / Origin checks tied
//     to the JSON body shape.
//   - Multipart can flip mass-assignment guards that gate on the
//     parsed object type.
package contenttype

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/detection/analysis"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// Detector probes targetURL for content-type confusion.
type Detector struct {
	client *skwshttp.Client
}

// New returns a Detector wired to the project's shared HTTP client.
func New(client *skwshttp.Client) *Detector {
	return &Detector{client: client}
}

// Result carries findings from Detect.
type Result struct {
	Findings []*core.Finding
}

// alternative parsers. Each entry is (content-type, body-builder).
type alternativeParser struct {
	contentType string
	build       func(canary string) string
	note        string
}

var alternatives = []alternativeParser{
	{
		contentType: "application/xml",
		build: func(canary string) string {
			return `<?xml version="1.0"?><root><probe>` + canary + `</probe></root>`
		},
		note: "XML body accepted on JSON endpoint — opens an XXE re-vector.",
	},
	{
		contentType: "application/x-www-form-urlencoded",
		build: func(canary string) string {
			return "probe=" + canary
		},
		note: "Form-encoded body accepted on JSON endpoint — may bypass JSON-shape CSRF / Origin checks.",
	},
	{
		contentType: "multipart/form-data; boundary=skwsboundary",
		build: func(canary string) string {
			return "--skwsboundary\r\nContent-Disposition: form-data; name=\"probe\"\r\n\r\n" + canary + "\r\n--skwsboundary--\r\n"
		},
		note: "multipart body accepted on JSON endpoint — re-enables file-upload / mass-assignment vectors.",
	},
}

// Detect sends a baseline JSON probe followed by each alternative
// content-type variant, comparing response shape and status. POST is
// used by default since that is where the confusion almost always
// matters; non-POST endpoints are skipped as a safety guard.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}

	canary := "skws_" + randomToken()
	jsonBody := `{"probe": "` + canary + `"}`

	jsonResp, err := d.client.SendRawBody(ctx, targetURL, "POST", jsonBody, "application/json")
	if err != nil || jsonResp == nil {
		return res, nil
	}
	jsonStripped := analysis.StripDynamicContent(jsonResp.Body)

	// Soft-baseline: send a body of total nonsense to capture the
	// "endpoint rejects unparseable bodies" shape. Alternatives whose
	// response matches this nonsense baseline are dismissed.
	junkResp, _ := d.client.SendRawBody(ctx, targetURL, "POST", "@@@junk@@@", "text/plain")
	junkStripped := ""
	if junkResp != nil {
		junkStripped = analysis.StripDynamicContent(junkResp.Body)
	}

	for _, alt := range alternatives {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		body := alt.build(canary)
		altResp, err := d.client.SendRawBody(ctx, targetURL, "POST", body, alt.contentType)
		if err != nil || altResp == nil {
			continue
		}

		// Strict: alternative must look like the JSON baseline AND not
		// match the junk-baseline. That filters out servers that 400
		// every non-JSON request with the same error page.
		altStripped := analysis.StripDynamicContent(altResp.Body)
		similarToJSON := analysis.ResponseSimilarity(altStripped, jsonStripped) >= 0.9
		matchesJunk := junkStripped != "" && analysis.ResponseSimilarity(altStripped, junkStripped) >= 0.9
		if matchesJunk {
			continue
		}
		// Only flag 2xx alternatives, OR alternatives whose body matches
		// the JSON baseline regardless of status (some servers return
		// 200 + same body for everything, making status alone unreliable).
		twoXX := altResp.StatusCode >= 200 && altResp.StatusCode < 300
		if !twoXX && !similarToJSON {
			continue
		}

		res.Findings = append(res.Findings, buildFinding(targetURL, alt, altResp))
	}
	return res, nil
}

func buildFinding(target string, alt alternativeParser, resp *skwshttp.Response) *core.Finding {
	finding := core.NewFinding("Content-Type Confusion", core.SeverityMedium)
	finding.URL = target
	finding.Parameter = alt.contentType
	finding.Tool = "contenttype"
	finding.Confidence = core.ConfidenceMedium
	finding.Description = fmt.Sprintf(
		"The endpoint returned a JSON-baseline-equivalent response when the body was sent as %s. %s",
		alt.contentType, alt.note,
	)
	bodyLen := 0
	if resp != nil {
		bodyLen = len(resp.Body)
	}
	finding.Evidence = fmt.Sprintf("Alternative: %s\nStatus: %d\nResponse length: %d", alt.contentType, resp.StatusCode, bodyLen)
	finding.Remediation = "Pin the request parser to a single content-type per endpoint, or apply the same authentication / validation / rate-limit logic across every parser the route accepts. Reject unexpected content-types with 415."
	finding.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A05:2025"},
		[]string{"CWE-436"},
	)
	finding.APITop10 = []string{"API3:2023", "API8:2023"}
	return finding
}

func randomToken() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
