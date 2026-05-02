// Package sse probes a target for unauthenticated Server-Sent Events
// streams. SSE endpoints often implement long-lived push notifications
// for things like order status, chat, admin dashboards, or live metrics.
// When the auth check is on the websocket-style upgrade path but not on
// the SSE path, an unauthenticated client can subscribe and receive
// every event the server emits.
//
// Detection is conservative: we GET each candidate path with
// `Accept: text/event-stream`, peek the first ~1KB of the response, and
// flag only when the server returns a 2xx Content-Type that begins
// "text/event-stream". 401 / 403 means the gate is working; 200 with a
// non-SSE body is just a regular HTML page.
package sse

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// candidatePaths is the wordlist of common SSE endpoints. Entries are
// root-relative; the detector resolves each against the target host.
var candidatePaths = []string{
	"/events",
	"/event-stream",
	"/eventsource",
	"/sse",
	"/stream",
	"/api/events",
	"/api/v1/events",
	"/api/v1/stream",
	"/api/v2/events",
	"/api/notifications/stream",
	"/notifications/stream",
	"/admin/events",
	"/_events",
	"/realtime",
	"/feed/stream",
}

// Detector probes the host for unauthenticated SSE endpoints.
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

// Detect probes every candidate path on targetURL's host. Severity is
// always High because an unauthenticated event stream typically leaks
// state that the application's UI hides behind login (per-user
// notifications, internal metrics, admin dashboards).
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	base, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}

	probeClient := d.client.Clone().WithHeaders(map[string]string{"Accept": "text/event-stream"})

	for _, path := range candidatePaths {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		probe := *base
		probe.Path = path
		probe.RawQuery = ""

		resp, err := probeClient.Get(ctx, probe.String())
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}
		if !isSSEResponse(resp.ContentType, resp.Body) {
			continue
		}

		res.Findings = append(res.Findings, buildFinding(probe.String(), path, resp))
	}
	return res, nil
}

// isSSEResponse reports whether the response is a Server-Sent Events
// stream. We trust the Content-Type header first; some servers omit
// it, in which case the canonical "data:" / "event:" / "id:" line
// prefix in the body is the next-most-reliable signal.
func isSSEResponse(contentType, body string) bool {
	if strings.HasPrefix(strings.ToLower(contentType), "text/event-stream") {
		return true
	}
	t := strings.TrimLeft(body, " \t\r\n")
	if t == "" {
		return false
	}
	return strings.HasPrefix(t, "data:") ||
		strings.HasPrefix(t, "event:") ||
		strings.HasPrefix(t, "id:") ||
		strings.HasPrefix(t, "retry:") ||
		strings.HasPrefix(t, ":")
}

func buildFinding(probedURL, path string, resp *skwshttp.Response) *core.Finding {
	finding := core.NewFinding("Unauthenticated Server-Sent Events Stream", core.SeverityHigh)
	finding.URL = probedURL
	finding.Parameter = path
	finding.Tool = "sse"
	finding.Confidence = core.ConfidenceHigh
	finding.Description = "The endpoint returned a text/event-stream response to an unauthenticated GET. SSE channels typically push state updates that the application's UI gates behind login, so an unauthenticated subscriber can listen to every event the server emits."
	bodyLen := 0
	if resp != nil {
		bodyLen = len(resp.Body)
	}
	finding.Evidence = fmt.Sprintf("Path: %s\nContent-Type: %s\nStatus: %d\nFirst-frame length: %d", path, resp.ContentType, resp.StatusCode, bodyLen)
	finding.Remediation = "Apply the same authentication gate to the SSE route as to the corresponding REST/WebSocket routes. If the stream is intentionally public, redact per-user / per-tenant fields server-side before pushing."
	finding.WithOWASPMapping(
		[]string{"WSTG-ATHN-04"},
		[]string{"A01:2025"},
		[]string{"CWE-306"},
	)
	finding.APITop10 = []string{"API2:2023", "API5:2023"}
	return finding
}
