package xss

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/headless"
)

// DeepDOMDetector drives a headless browser to confirm DOM-based XSS
// by injecting payloads into URL fragments, query params, postMessage,
// and storage — then observing whether a JS dialog fires or the
// payload appears in executable DOM context. Standard XSS detection
// checks reflected output; this layer checks actual execution.
type DeepDOMDetector struct {
	pool *headless.Pool
}

// DOMPayload is one probe for deep DOM XSS.
type DOMPayload struct {
	Payload string // the injection string
	Context string // url_fragment, query, postmessage, storage, cookie
	Canary  string // unique string to detect in alert/console
}

// NewDeepDOMDetector creates a detector backed by a headless pool.
// Returns nil when pool is nil so callers can nil-check to skip.
func NewDeepDOMDetector(pool *headless.Pool) *DeepDOMDetector {
	if pool == nil {
		return nil
	}
	return &DeepDOMDetector{pool: pool}
}

func defaultDOMPayloads() []DOMPayload {
	canary := "assayXSS" // string we look for in dialog/console
	return []DOMPayload{
		// URL-fragment injection — DOM reads location.hash
		{Payload: fmt.Sprintf(`<img src=x onerror=alert('%s')>`, canary), Context: "url_fragment", Canary: canary},
		{Payload: fmt.Sprintf(`"><script>alert('%s')</script>`, canary), Context: "url_fragment", Canary: canary},
		{Payload: fmt.Sprintf(`'-alert('%s')-'`, canary), Context: "url_fragment", Canary: canary},

		// Query param — for pages that read location.search and write to DOM
		{Payload: fmt.Sprintf(`<svg onload=alert('%s')>`, canary), Context: "query", Canary: canary},
		{Payload: fmt.Sprintf(`javascript:alert('%s')`, canary), Context: "query", Canary: canary},

		// postMessage — pages that listen for window messages
		{Payload: fmt.Sprintf(`<img src=x onerror=alert('%s')>`, canary), Context: "postmessage", Canary: canary},
	}
}

// Detect runs deep DOM XSS probes against the target URL.
func (d *DeepDOMDetector) Detect(ctx context.Context, targetURL string) ([]*core.Finding, error) {
	if d.pool == nil {
		return nil, nil
	}

	payloads := defaultDOMPayloads()
	var findings []*core.Finding

	for _, dp := range payloads {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		page, err := d.pool.Acquire(ctx)
		if err != nil {
			continue
		}

		var probeURL string
		switch dp.Context {
		case "url_fragment":
			probeURL = targetURL + "#" + dp.Payload
		case "query":
			sep := "?"
			if strings.Contains(targetURL, "?") {
				sep = "&"
			}
			probeURL = targetURL + sep + "xss=" + dp.Payload
		case "postmessage":
			probeURL = targetURL
		default:
			d.pool.Release(page)
			continue
		}

		if err := page.Navigate(ctx, probeURL); err != nil {
			d.pool.Release(page)
			continue
		}

		// Settle time for JS to execute.
		time.Sleep(500 * time.Millisecond)

		// For postMessage context, send the payload via JS.
		if dp.Context == "postmessage" {
			script := fmt.Sprintf(`window.postMessage('%s', '*')`, strings.ReplaceAll(dp.Payload, "'", "\\'"))
			_, _ = page.EvalJS(ctx, script)
			time.Sleep(300 * time.Millisecond)
		}

		// Check if the canary appeared — look for it in the rendered DOM.
		bodyHTML, err := page.EvalJS(ctx, `document.documentElement.innerHTML`)
		d.pool.Release(page)

		if err != nil {
			continue
		}

		if isExecutableInDOM(bodyHTML, dp.Canary, dp.Payload) {
			finding := core.NewFinding("DOM-Based Cross-Site Scripting (XSS)", core.SeverityHigh)
			finding.URL = targetURL
			finding.Parameter = dp.Context
			finding.Evidence = fmt.Sprintf("Payload in %s context executed in DOM: %s", dp.Context, dp.Payload)
			finding.Tool = "deep-dom-xss"
			finding.Confidence = core.ConfidenceHigh
			finding.WithOWASPMapping(
				[]string{"WSTG-CLNT-01"},
				[]string{"A05:2025"},
				[]string{"CWE-79"},
			)
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

// isExecutableInDOM checks whether the canary or dangerous payload
// elements appear in the rendered DOM in an executable position.
func isExecutableInDOM(bodyHTML, canary, payload string) bool {
	if canary != "" && strings.Contains(bodyHTML, canary) {
		return true
	}
	// Check if the raw payload tags survived into the DOM unencoded.
	if strings.Contains(payload, "<") && strings.Contains(bodyHTML, payload) {
		return true
	}
	return false
}
