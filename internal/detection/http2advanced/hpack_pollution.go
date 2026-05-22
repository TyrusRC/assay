package http2advanced

import (
	"context"
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/TyrusRC/assay/internal/core"
)

// DetectHPACKPollution opens stream 1 with a probe header (added to the
// HPACK dynamic table), then opens stream 3 with NO x-test header. If the
// stream-3 response surfaces the stream-1 probe value (in headers, the
// :status pseudo-header, or echoed via a custom header the handler set),
// the server is leaking HPACK state across streams.
func (d *Detector) DetectHPACKPollution(ctx context.Context, opts DetectOptions) (*DetectionResult, error) {
	res := &DetectionResult{DetectionType: "hpack-pollution"}

	sess, ok := d.openH2Session(ctx, opts)
	if !ok {
		return res, nil
	}
	defer sess.close()

	const probeMarker = "assay-hpack-probe-marker-3f9e2c1a"

	// Stream 1: GET with x-test: probeMarker → adds the entry to the
	// HPACK dynamic table.
	hdr1 := encodeHeaders(sess.u, []hpack.HeaderField{{Name: "x-test", Value: probeMarker}})
	if err := writeRequestHeaders(sess.framer, 1, hdr1); err != nil {
		return res, nil
	}
	// Stream 3: GET with NO x-test. A correct decoder emits no x-test.
	if err := writeRequestHeaders(sess.framer, 3, encodeHeaders(sess.u, nil)); err != nil {
		return res, nil
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	headersByStream := readResponseHeaders(sess.framer, time.Now().Add(timeout))
	for _, hf := range headersByStream[3] {
		if strings.Contains(strings.ToLower(hf.Value), probeMarker) {
			res.Vulnerable = true
			res.Findings = append(res.Findings, buildHPACKPollutionFinding(sess.u.String(), sess.host, probeMarker, hf))
			return res, nil
		}
	}
	return res, nil
}

// readResponseHeaders pumps frames until either:
//   - deadline elapses,
//   - the framer returns an error (connection closed / framer broken),
//   - we have a HEADERS frame for every expected stream and END_STREAM is
//     observed (we settle for "at least one HEADERS per stream" because
//     the server may keep sending DATA frames we don't care about).
//
// Returned map is keyed by stream ID -> the decoded header fields of the
// first HEADERS frame seen on that stream.
func readResponseHeaders(framer *http2.Framer, end time.Time) map[uint32][]hpack.HeaderField {
	out := make(map[uint32][]hpack.HeaderField)
	dec := hpack.NewDecoder(4096, nil)
	for time.Now().Before(end) {
		f, err := framer.ReadFrame()
		if err != nil {
			return out
		}
		hf, ok := f.(*http2.HeadersFrame)
		if !ok {
			continue
		}
		fields, derr := dec.DecodeFull(hf.HeaderBlockFragment())
		if derr != nil {
			continue
		}
		if _, seen := out[hf.StreamID]; !seen {
			out[hf.StreamID] = fields
		}
		// Stop once we've seen at least two streams (1 and 3 in the
		// HPACK probe).
		if len(out) >= 2 {
			return out
		}
	}
	return out
}

// buildHPACKPollutionFinding builds the Critical-severity finding for
// cross-stream HPACK dynamic-table leakage.
func buildHPACKPollutionFinding(target, host, marker string, leaked hpack.HeaderField) *core.Finding {
	f := core.NewFinding("HTTP/2 HPACK Cross-Stream Pollution", core.SeverityCritical)
	f.URL = target
	f.Tool = toolName
	f.Confidence = core.ConfidenceHigh
	f.Description = fmt.Sprintf(
		"A header value set only on stream 1 (x-test=%s) was observed in the response headers of stream 3, which never carried that header. This indicates the server's HPACK decoder is leaking dynamic-table state across streams — a critical isolation failure that can leak headers (including Authorization, Cookie) between concurrent requests on the same H/2 connection.",
		marker,
	)
	f.Evidence = fmt.Sprintf("Host: %s\nALPN: h2\nProbe marker (set on stream 1 only): %s\nLeaked header on stream 3: %s=%s",
		host, marker, leaked.Name, leaked.Value)
	f.Remediation = "Upgrade the HTTP/2 stack to a version that maintains per-stream HPACK decoder state (or, more precisely, applies the dynamic-table mutations from each HEADERS block atomically against a single connection-shared table without re-emitting prior entries on new streams). Audit the request pipeline for any code path that caches decoded HeaderFields between streams."
	f.WithOWASPMapping(
		[]string{"WSTG-INPV-12"},
		[]string{"A02:2025"},
		[]string{"CWE-400", "CWE-770"},
	)
	f.APITop10 = []string{"API8:2023"}
	return f
}
