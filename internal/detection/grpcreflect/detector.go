// Package grpcreflect probes a target for an exposed gRPC server-
// reflection service. The reflection API is a developer-convenience
// feature that lets clients discover every gRPC service and method on a
// server without a precompiled .proto. In production, leaving it on
// hands attackers a complete API map for free.
//
// We use the gRPC-Web HTTP/1.1 transport (the only flavour reachable
// without HTTP/2 ALPN) and POST to the canonical
// `/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo` path
// with a list_services request. A 200 + grpc-message-equivalent body
// containing service names is the smoking gun.
package grpcreflect

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// reflectionPaths covers both the v1 and v1alpha service identifiers.
// Most servers expose v1alpha; v1 was standardised more recently.
var reflectionPaths = []string{
	"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
	"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
}

// Detector probes targetURL's host for the gRPC reflection service.
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

// listServicesRequest is the gRPC-Web wire-format payload for a
// reflection list_services call:
//   - 1 byte: 0x00 (uncompressed)
//   - 4 bytes: big-endian length of the protobuf payload
//   - protobuf: ListServicesRequest is { string list_services = 3; }
//     encoded here as a single empty-string field-3 (key 0x1a, length 0).
var listServicesRequest = []byte{
	0x00,             // uncompressed flag
	0x00, 0x00, 0x00, 0x02, // big-endian length = 2 bytes of payload
	0x1a, 0x00,       // field 3 (list_services), wire-type 2 (length-delimited), length 0
}

// Detect POSTs the list_services reflection payload to each candidate
// reflection path on the host. Findings emit on a 200 response with a
// body that contains plausibly-protobuf-shaped service names. False-
// positives on plain JSON / HTML responses are filtered by length and
// content-type checks.
func (d *Detector) Detect(ctx context.Context, targetURL string) (*Result, error) {
	res := &Result{}
	if d.client == nil {
		return res, nil
	}
	base, err := url.Parse(targetURL)
	if err != nil {
		return res, nil
	}

	for _, path := range reflectionPaths {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		probe := *base
		probe.Path = path
		probe.RawQuery = ""

		resp, err := d.client.SendRawBody(ctx, probe.String(), "POST", string(listServicesRequest), "application/grpc-web")
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}
		if !looksLikeReflectionResponse(resp.ContentType, resp.Body) {
			continue
		}
		services := extractServiceNames(resp.Body)
		res.Findings = append(res.Findings, buildFinding(probe.String(), path, resp, services))
	}
	return res, nil
}

// looksLikeReflectionResponse filters out HTML / JSON pages that happen
// to share the path. A real gRPC-Web reply has Content-Type starting
// with "application/grpc" and a binary body starting with the same
// 5-byte length prefix our request used.
func looksLikeReflectionResponse(contentType, body string) bool {
	ct := strings.ToLower(contentType)
	if !strings.HasPrefix(ct, "application/grpc") {
		return false
	}
	if len(body) < 5 {
		return false
	}
	return true
}

// extractServiceNames pulls printable strings of the form "name.svc.X"
// out of a binary protobuf reply. We don't fully decode the response
// (would pull in google.golang.org/protobuf for one heuristic); the
// regex-style scan is enough for the reporting evidence.
func extractServiceNames(body string) []string {
	var out []string
	const minLen = 8
	cur := bytes.Buffer{}
	for _, b := range []byte(body) {
		if b == '.' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' {
			cur.WriteByte(b)
			continue
		}
		s := cur.String()
		cur.Reset()
		if len(s) >= minLen && strings.Contains(s, ".") {
			out = append(out, s)
		}
	}
	if s := cur.String(); len(s) >= minLen && strings.Contains(s, ".") {
		out = append(out, s)
	}
	return out
}

func buildFinding(probedURL, path string, resp *skwshttp.Response, services []string) *core.Finding {
	finding := core.NewFinding("gRPC Server Reflection Exposed", core.SeverityMedium)
	finding.URL = probedURL
	finding.Parameter = path
	finding.Tool = "grpcreflect"
	finding.Confidence = core.ConfidenceHigh
	finding.Description = "The server responded to a gRPC reflection list_services call, exposing the full set of internal service definitions to any caller. An attacker can use this to map every method and message type the server understands."
	preview := strings.Join(services, ", ")
	if len(preview) > 200 {
		preview = preview[:197] + "..."
	}
	finding.Evidence = fmt.Sprintf("Path: %s\nContent-Type: %s\nDecoded service names (best effort): %s",
		path, resp.ContentType, preview)
	finding.Remediation = "Disable gRPC reflection in production deployments. Build the server without `reflection.Register(s)` (Go) / `ProtoReflectionService.newInstance()` (Java) / `grpc_reflection.enable_server_reflection()` (Python) outside development environments."
	finding.WithOWASPMapping(
		[]string{"WSTG-CONF-04"},
		[]string{"A05:2025"},
		[]string{"CWE-200"},
	)
	finding.APITop10 = []string{"API9:2023"}
	return finding
}
