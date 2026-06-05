package verification

import (
	"context"
	"net/url"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	httpx "github.com/TyrusRC/assay/internal/http"
)

// openRedirectVerifier confirms an open redirect by injecting an off-site
// destination at the vulnerable parameter and checking that the server emits a
// 3xx whose Location actually points at the attacker-controlled host.
type openRedirectVerifier struct{}

func (openRedirectVerifier) Verify(ctx context.Context, f *core.Finding, client *httpx.Client) (*Proof, error) {
	if f.Parameter == "" {
		return nil, nil
	}
	token := marker()
	dest := "https://" + token + ".verify.example/"

	noFollow := client.Clone().WithFollowRedirects(false)
	resp, err := noFollow.SendPayload(ctx, f.URL, f.Parameter, dest, requestMethod(f))
	if err != nil || resp == nil {
		return nil, err
	}
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return &Proof{Confirmed: false}, nil
	}
	loc := resp.RawHeaders.Get("Location")
	if loc == "" {
		loc = resp.Headers["Location"]
	}
	if !pointsTo(loc, token) {
		return &Proof{Confirmed: false}, nil
	}
	return &Proof{
		Confirmed: true,
		Method:    "location-header",
		Detail:    "redirect Location resolves to attacker-controlled host: " + loc,
	}, nil
}

// pointsTo reports whether a Location header sends the browser to a host
// carrying our unique token — i.e. an off-site redirect we control. Matching on
// the host (not a substring) avoids false positives where the token merely
// appears in a query string on a same-site redirect.
func pointsTo(location, token string) bool {
	if location == "" {
		return false
	}
	u, err := url.Parse(strings.TrimSpace(location))
	if err != nil {
		return false
	}
	return strings.Contains(u.Host, token)
}

// reflectedXSSVerifier confirms reflected XSS by injecting a marker wrapped in
// HTML metacharacters and checking that the angle brackets survive unencoded in
// the response — the precondition for breaking out into an executable context.
// This is a high-confidence reflection proof; it is intentionally conservative
// and does not claim execution (a headless verifier covers that separately).
type reflectedXSSVerifier struct{}

func (reflectedXSSVerifier) Verify(ctx context.Context, f *core.Finding, client *httpx.Client) (*Proof, error) {
	if f.Parameter == "" {
		return nil, nil
	}
	token := marker()
	payload := "\"><" + token + ">"

	resp, err := client.SendPayload(ctx, f.URL, f.Parameter, payload, requestMethod(f))
	if err != nil || resp == nil {
		return nil, err
	}
	if !strings.Contains(resp.Body, "<"+token+">") {
		return &Proof{Confirmed: false}, nil
	}
	return &Proof{
		Confirmed: true,
		Method:    "reflection-unencoded",
		Detail:    "injected marker reflected with unencoded angle brackets",
	}, nil
}
