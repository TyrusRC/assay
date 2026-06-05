package verification

import (
	"context"
	"net/url"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	httpx "github.com/TyrusRC/assay/internal/http"
)

// sstiVerifier confirms server-side template injection by injecting an
// arithmetic expression with distinctive operands and checking that the product
// appears in the response while the literal expression does not — proof the
// template engine evaluated it rather than merely reflecting it.
type sstiVerifier struct{}

// 7331 * 7 = 51317 — operands chosen to be unlikely to occur by coincidence.
const (
	sstiExpr    = "7331*7"
	sstiProduct = "51317"
)

func (sstiVerifier) Verify(ctx context.Context, f *core.Finding, client *httpx.Client) (*Proof, error) {
	if f.Parameter == "" {
		return nil, nil
	}
	payloads := []string{
		"{{" + sstiExpr + "}}", "${" + sstiExpr + "}", "#{" + sstiExpr + "}",
		"<%= " + sstiExpr + " %>", "{" + sstiExpr + "}", "*{" + sstiExpr + "}",
	}
	for _, p := range payloads {
		resp, err := client.SendPayload(ctx, f.URL, f.Parameter, p, requestMethod(f))
		if err != nil || resp == nil {
			continue
		}
		if strings.Contains(resp.Body, sstiProduct) && !strings.Contains(resp.Body, sstiExpr) {
			return &Proof{
				Confirmed: true,
				Method:    "template-evaluation",
				Detail:    "injected " + p + " evaluated to " + sstiProduct + " in the response",
			}, nil
		}
	}
	return &Proof{Confirmed: false}, nil
}

// lfiVerifier confirms local file inclusion / path traversal by attempting to
// read a well-known system file and checking for its signature content.
type lfiVerifier struct{}

func (lfiVerifier) Verify(ctx context.Context, f *core.Finding, client *httpx.Client) (*Proof, error) {
	if f.Parameter == "" {
		return nil, nil
	}
	payloads := []string{
		"/etc/passwd", "../../../../../../etc/passwd",
		"....//....//....//....//....//etc/passwd",
		"/windows/win.ini", "..\\..\\..\\..\\windows\\win.ini",
	}
	for _, p := range payloads {
		resp, err := client.SendPayload(ctx, f.URL, f.Parameter, p, requestMethod(f))
		if err != nil || resp == nil {
			continue
		}
		if marker := fileMarker(resp.Body); marker != "" {
			return &Proof{
				Confirmed: true,
				Method:    "file-content-disclosure",
				Detail:    "traversal payload returned " + marker + " content",
			}, nil
		}
	}
	return &Proof{Confirmed: false}, nil
}

// fileMarker returns the name of a sensitive file whose signature content is
// present in body, or "" when none is found.
func fileMarker(body string) string {
	if strings.Contains(body, "root:") && strings.Contains(body, ":0:0:") {
		return "/etc/passwd"
	}
	low := strings.ToLower(body)
	if strings.Contains(low, "[extensions]") || strings.Contains(low, "[fonts]") ||
		strings.Contains(low, "16-bit app support") {
		return "win.ini"
	}
	return ""
}

// crlfVerifier confirms CRLF/header injection by injecting a CRLF sequence that
// adds a uniquely named response header and checking the header comes back.
type crlfVerifier struct{}

func (crlfVerifier) Verify(ctx context.Context, f *core.Finding, client *httpx.Client) (*Proof, error) {
	if f.Parameter == "" {
		return nil, nil
	}
	token := marker()
	// Raw CR/LF; SendPayload percent-encodes them once for the query string,
	// and a vulnerable app decodes them back into a header break.
	payload := "\r\nX-Assay-Verify: " + token
	resp, err := client.SendPayload(ctx, f.URL, f.Parameter, payload, requestMethod(f))
	if err != nil || resp == nil {
		return nil, err
	}
	if resp.RawHeaders.Get("X-Assay-Verify") == token {
		return &Proof{
			Confirmed: true,
			Method:    "header-injection",
			Detail:    "injected CRLF added the response header X-Assay-Verify",
		}, nil
	}
	return &Proof{Confirmed: false}, nil
}

// sqliBooleanVerifier confirms boolean-based SQL injection by sending a TRUE and
// a FALSE condition and requiring the TRUE response to be stable across a repeat
// while differing materially from the FALSE response — the boolean oracle.
type sqliBooleanVerifier struct{}

func (sqliBooleanVerifier) Verify(ctx context.Context, f *core.Finding, client *httpx.Client) (*Proof, error) {
	if f.Parameter == "" {
		return nil, nil
	}
	base := origValue(f)
	pairs := [][2]string{
		{base + "' AND '1'='1", base + "' AND '1'='2"},
		{base + " AND 1=1", base + " AND 1=2"},
		{base + "' AND '1'='1'-- -", base + "' AND '1'='2'-- -"},
	}
	for _, pair := range pairs {
		t1 := bodyLen(ctx, client, f, pair[0])
		if t1 < 0 {
			continue
		}
		fl := bodyLen(ctx, client, f, pair[1])
		if fl < 0 {
			continue
		}
		t2 := bodyLen(ctx, client, f, pair[0])
		// TRUE must be reproducible and clearly distinct from FALSE.
		if t1 == t2 && absDiff(t1, fl) > sqliLenDelta {
			return &Proof{
				Confirmed: true,
				Method:    "boolean-oracle",
				Detail:    "TRUE/FALSE conditions yield stable, materially different responses",
			}, nil
		}
	}
	return &Proof{Confirmed: false}, nil
}

// sqliLenDelta is the minimum body-length difference between a TRUE and FALSE
// condition to treat as a boolean oracle rather than noise.
const sqliLenDelta = 16

// bodyLen sends payload at the finding's parameter and returns the response body
// length, or -1 on error.
func bodyLen(ctx context.Context, client *httpx.Client, f *core.Finding, payload string) int {
	resp, err := client.SendPayload(ctx, f.URL, f.Parameter, payload, requestMethod(f))
	if err != nil || resp == nil {
		return -1
	}
	return len(resp.Body)
}

// origValue returns the finding parameter's current value from its URL, or "1".
func origValue(f *core.Finding) string {
	u, err := url.Parse(f.URL)
	if err != nil {
		return "1"
	}
	if v := u.Query().Get(f.Parameter); v != "" {
		return v
	}
	return "1"
}

func absDiff(a, b int) int {
	if a < b {
		return b - a
	}
	return a - b
}
