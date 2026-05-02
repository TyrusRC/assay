package domdetect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
)

// XSSResult is what DetectXSS returns. Findings is empty when nothing was
// detected; on detection it carries one finding per vulnerable parameter.
type XSSResult struct {
	Findings []*core.Finding
}

// DetectXSS probes each query parameter on targetURL for DOM-based XSS.
// For each param we inject a payload that, if executed by client JS, sets
// `window[<sentinel>] = "HIT"`. After navigation we eval `window[<sentinel>]`;
// if the marker echoes back, the parameter feeds a JS sink and we emit a
// High-severity finding. Pure server-side reflection cannot trigger this —
// the value has to be evaluated by the browser.
//
// Each param gets its own per-probe sentinel so two concurrent probes
// (different params, possibly across goroutines later) cannot cross-pollute.
func DetectXSS(ctx context.Context, runner Runner, targetURL string) (*XSSResult, error) {
	res := &XSSResult{}
	if runner == nil {
		return res, nil
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return res, fmt.Errorf("parse target: %w", err)
	}
	params := u.Query()
	if len(params) == 0 {
		return res, nil
	}

	for paramName := range params {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		sentinel := newSentinel("skwsDomXss")
		// `<img onerror>` is the most reliable sink for HTML reflection;
		// JS-context sinks (innerHTML insertion of unencoded value) eval
		// it just as well.
		payload := fmt.Sprintf(`"><img src=x onerror="window.%s='HIT'">`, sentinel)

		probeURL := setQueryParam(u, paramName, payload)
		if err := runner.Navigate(ctx, probeURL); err != nil {
			continue
		}

		got, err := runner.EvalJS(ctx, fmt.Sprintf(`window.%s || ""`, sentinel))
		if err != nil {
			continue
		}
		if !strings.Contains(got, "HIT") {
			continue
		}

		finding := core.NewFinding("DOM-Based Cross-Site Scripting (XSS)", core.SeverityHigh)
		finding.URL = targetURL
		finding.Parameter = paramName
		finding.Description = fmt.Sprintf(
			"DOM-based XSS detected in '%s' parameter. The injected payload was reflected into a JavaScript-executing sink (innerHTML / eval-style), and the canary marker fired in the browser context.",
			paramName,
		)
		finding.Evidence = fmt.Sprintf("Payload: %s\nMarker fired: window.%s = %q", payload, sentinel, got)
		finding.Tool = "domxss-detector"
		finding.Confidence = core.ConfidenceHigh
		finding.Remediation = "Encode user input before inserting into the DOM. Use textContent / setAttribute / safe templating libraries; never pass untrusted strings to innerHTML, eval, or Function()."
		finding.WithOWASPMapping(
			[]string{"WSTG-CLNT-01"},
			[]string{"A03:2025"},
			[]string{"CWE-79"},
		)
		res.Findings = append(res.Findings, finding)
	}
	return res, nil
}

// setQueryParam returns a fresh URL string with paramName=value, preserving
// every other parameter on u. Operates on a clone so the caller's url.URL
// is never mutated.
func setQueryParam(u *url.URL, paramName, value string) string {
	clone := *u
	q := clone.Query()
	q.Set(paramName, value)
	clone.RawQuery = q.Encode()
	return clone.String()
}

// newSentinel returns a unique JS-identifier-safe sentinel name. The
// 8-byte random suffix collides with probability ~10^-19, more than
// enough for any realistic scan.
func newSentinel(prefix string) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}
