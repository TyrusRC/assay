package paddingoracle

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	assayhttp "github.com/TyrusRC/assay/internal/http"
)

// maxProbeCap is the hard upper bound on probes per detection call.
// 256 covers every possible value of a single byte, which is enough
// to discover the ~1-in-256 "valid padding" response in a CBC oracle.
const maxProbeCap = 256

// defaultProbeBudget is used when DetectOptions.MaxProbes is zero.
// 32 byte values are sufficient to exhibit at least one valid-vs-
// invalid bucket split when an oracle is present, while keeping the
// network cost low for a default probe.
const defaultProbeBudget = 32

// minBucketsForOracle is the threshold at which a server's responses
// are considered discriminable. Any constant-time, constant-shape
// implementation will produce exactly one bucket across all 256
// candidate bytes; two or more buckets indicate that the server is
// leaking padding-validity information.
const minBucketsForOracle = 2

// bodyLengthBandTolerance defines the ±5% body-length window inside
// which two responses are treated as the same bucket. This swallows
// minor variations (timestamps, request IDs) without losing the
// ~order-of-magnitude size gap between a real "OK" page and a server
// error page.
const bodyLengthBandTolerance = 0.05

// timeBandMs widens the response-time bucket. CBC padding-oracle
// servers historically leak via timing as well as status code, but
// loopback timing on httptest jitters substantially; 50ms is a
// reasonable signal floor.
const timeBandMs = 50

// DetectOptions configures DetectFromToken. Zero values fall back to
// package defaults (base64 encoding, 32 probes, 30s timeout).
type DetectOptions struct {
	// Encoding is "base64" (default) or "hex". Empty -> base64.
	Encoding string
	// MaxProbes caps the number of last-byte mutations. Values above
	// maxProbeCap (256) are clamped down; zero -> defaultProbeBudget.
	MaxProbes int
	// Timeout caps total time spent probing. Zero -> 30s.
	Timeout time.Duration
}

// DetectionResult carries the verdict and supporting findings.
type DetectionResult struct {
	// Vulnerable is true when the server's responses fell into >= 2
	// distinct buckets across the probe set.
	Vulnerable bool
	// Findings is non-empty when Vulnerable is true.
	Findings []*core.Finding
	// DistinctBuckets is the count of unique (status, body-band,
	// time-band) tuples observed across the probe set.
	DistinctBuckets int
}

// Detector probes endpoints for CBC padding-oracle behavior.
type Detector struct {
	client *assayhttp.Client
}

// New returns a Detector wired to the project's shared HTTP client.
// A nil client is permitted; DetectFromToken returns an empty result
// in that case rather than panicking.
func New(client *assayhttp.Client) *Detector {
	return &Detector{client: client}
}

// responseBucket captures the response shape signals we group by.
type responseBucket struct {
	status    int
	bodyBand  int
	timeBand  int
	exemplar  string // first byte value (as hex) that produced this bucket
	bodyLen   int
	durationM int64
}

// DetectFromToken probes targetURL for a CBC padding oracle by
// flipping the last byte of the decoded token (originalToken) across
// up to opts.MaxProbes byte values and bucketing the responses. The
// targetURL may carry the parameter already; DetectFromToken
// overwrites paramName's value with each tampered token.
//
// Returns ErrEmptyToken if originalToken is empty,
// ErrUnsupportedEncoding for encodings other than "base64"/"hex",
// or a decode error if the token is malformed for the selected
// encoding.
func (d *Detector) DetectFromToken(
	ctx context.Context,
	targetURL string,
	paramName string,
	originalToken string,
	opts DetectOptions,
) (*DetectionResult, error) {
	res := &DetectionResult{}
	if d.client == nil {
		return res, nil
	}
	if strings.TrimSpace(originalToken) == "" {
		return nil, ErrEmptyToken
	}
	encoding := normaliseEncoding(opts.Encoding)
	if encoding == "" {
		return nil, ErrUnsupportedEncoding
	}
	raw, err := decodeToken(originalToken, encoding)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}
	if len(raw) == 0 {
		return nil, ErrEmptyToken
	}

	probeBudget := opts.MaxProbes
	if probeBudget <= 0 {
		probeBudget = defaultProbeBudget
	}
	if probeBudget > maxProbeCap {
		probeBudget = maxProbeCap
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	buckets := make(map[responseBucket]int)
	var evidence strings.Builder

	originalLast := raw[len(raw)-1]
	client := d.client.Clone().WithFollowRedirects(false)

	for i := 0; i < probeBudget; i++ {
		// Walk the byte space starting at originalLast so the most
		// likely "valid padding" byte appears first in evidence.
		candidate := byte((int(originalLast) + i) & 0xff)

		select {
		case <-probeCtx.Done():
			return nil, probeCtx.Err()
		default:
		}

		mutated := make([]byte, len(raw))
		copy(mutated, raw)
		mutated[len(mutated)-1] = candidate
		tampered := encodeToken(mutated, encoding)

		probeURL, err := injectParam(targetURL, paramName, tampered)
		if err != nil {
			return nil, fmt.Errorf("build probe URL: %w", err)
		}

		resp, err := client.Get(probeCtx, probeURL)
		if err != nil || resp == nil {
			// Transport-level failures (timeout, reset) collapse into
			// a distinct bucket so they still contribute to the
			// "responses differ" signal; treat them as status=0.
			b := responseBucket{status: 0, bodyBand: 0, timeBand: 0, exemplar: fmt.Sprintf("%02x", candidate)}
			buckets[b]++
			continue
		}

		bodyLen := len(resp.Body)
		bb := bodyBand(bodyLen)
		tb := timeBand(resp.Duration)
		b := responseBucket{
			status:    resp.StatusCode,
			bodyBand:  bb,
			timeBand:  tb,
			bodyLen:   bodyLen,
			durationM: resp.Duration.Milliseconds(),
		}
		// Tag exemplar only on first sighting so the bucket key stays
		// stable for the map.
		key := responseBucket{status: b.status, bodyBand: b.bodyBand, timeBand: b.timeBand}
		buckets[key]++
		if buckets[key] == 1 {
			fmt.Fprintf(&evidence, "byte=0x%02x -> status=%d body=%dB time=%dms\n",
				candidate, resp.StatusCode, bodyLen, resp.Duration.Milliseconds())
		}
	}

	res.DistinctBuckets = len(buckets)
	if len(buckets) < minBucketsForOracle {
		return res, nil
	}

	res.Vulnerable = true
	finding := buildFinding(targetURL, paramName, evidence.String(), len(buckets))
	res.Findings = append(res.Findings, finding)
	return res, nil
}

// ErrEmptyToken is returned when the caller passes an empty token.
var ErrEmptyToken = errors.New("paddingoracle: original token is empty")

// ErrUnsupportedEncoding is returned when DetectOptions.Encoding is
// not "base64" or "hex".
var ErrUnsupportedEncoding = errors.New("paddingoracle: unsupported encoding (expected base64 or hex)")

// normaliseEncoding lowers/trims the input and maps "" to "base64".
// Returns the canonical form or "" for unsupported values.
func normaliseEncoding(in string) string {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case "", "base64", "b64":
		return "base64"
	case "hex", "base16":
		return "hex"
	default:
		return ""
	}
}

// decodeToken converts the wire-form token back to raw bytes.
// Base64 decoding tolerates both standard and URL-safe alphabets so
// the detector works against tokens carried in URL parameters.
func decodeToken(token, encoding string) ([]byte, error) {
	switch encoding {
	case "hex":
		return hex.DecodeString(token)
	default:
		if strings.ContainsAny(token, "-_") {
			return base64.URLEncoding.DecodeString(token)
		}
		// Add padding for un-padded base64 some apps emit.
		t := token
		if pad := len(t) % 4; pad != 0 {
			t = t + strings.Repeat("=", 4-pad)
		}
		return base64.StdEncoding.DecodeString(t)
	}
}

// encodeToken is the inverse of decodeToken for the same encoding.
func encodeToken(raw []byte, encoding string) string {
	if encoding == "hex" {
		return hex.EncodeToString(raw)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// injectParam overwrites paramName's value in targetURL. If targetURL
// has no query at all, the parameter is appended.
func injectParam(targetURL, paramName, value string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(paramName, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// bodyBand reduces body length to a coarse band so responses that
// differ by a few bytes (timestamps, request IDs) stay in the same
// bucket. We anchor at length=1 to avoid log(0).
func bodyBand(n int) int {
	if n <= 0 {
		return 0
	}
	width := int(math.Ceil(float64(n) * bodyLengthBandTolerance))
	if width < 1 {
		width = 1
	}
	return n / width
}

// timeBand groups response times in timeBandMs windows.
func timeBand(d time.Duration) int {
	return int(d.Milliseconds() / timeBandMs)
}

// buildFinding renders the core.Finding emitted when an oracle is
// detected.
func buildFinding(targetURL, paramName, evidence string, buckets int) *core.Finding {
	f := core.NewFinding("Padding Oracle", core.SeverityCritical)
	f.Title = "CBC Padding Oracle (WSTG-CRYP-02)"
	f.URL = targetURL
	f.Parameter = paramName
	f.Tool = "paddingoracle-detector"
	f.Confidence = core.ConfidenceHigh
	f.Description = "The server's response shape (status code, body length, response time) varied across last-byte mutations of the encrypted token. A CBC padding oracle leaks one byte of plaintext per ~256 requests and allows complete recovery of the underlying plaintext, including session-binding material and any encrypted secrets the token carries (Vaudenay 2002)."
	f.Evidence = fmt.Sprintf("Distinct response buckets: %d\n%s", buckets, evidence)
	f.Remediation = "Authenticate ciphertexts before decrypting them: switch from CBC-only to AES-GCM (or CBC+HMAC with constant-time verification, encrypt-then-MAC), and ensure decryption failures, MAC failures, and padding failures all return the SAME response (same status, same body, same timing). Reject any change in ciphertext bytes from the issued token. Rotate any keys that were used while the oracle was reachable."
	f.WithOWASPMapping(
		[]string{"WSTG-CRYP-02"},
		[]string{"A04:2025"},
		[]string{"CWE-209", "CWE-327"},
	)
	f.References = []string{
		"https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle",
		"https://www.iacr.org/cryptodb/data/paper.php?pubkey=1232",
	}
	return f
}
