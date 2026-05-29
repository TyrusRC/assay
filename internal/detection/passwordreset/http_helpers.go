package passwordreset

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/TyrusRC/assay/internal/http"
)

// requestToken issues a reset request for the given user and returns
// the issued token if one can be extracted from the response body. The
// returned URL is the request endpoint actually used, so the confirm
// step can derive a sibling URL if hints were applied.
func (d *Detector) requestToken(ctx context.Context, resetURL, user string) (string, string, error) {
	body := buildRequestBody(user)

	for _, hint := range requestPathHints {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		default:
		}

		u := joinPath(resetURL, hint)
		resp, err := d.client.SendRawBody(ctx, u, "POST", body, "application/json")
		if err != nil || resp == nil {
			continue
		}
		token := extractToken(resp.Body)
		if token != "" {
			return token, u, nil
		}
	}
	return "", resetURL, nil
}

// tokenRegex captures the most common JSON shapes used to return a
// reset token. We avoid HTML scraping — JSON is by far the dominant
// reset-API shape and HTML inspection is a separate problem.
var tokenRegex = regexp.MustCompile(`"(?:token|reset_token|resetToken|code)"\s*:\s*"([^"]+)"`)

func extractToken(body string) string {
	if m := tokenRegex.FindStringSubmatch(body); len(m) == 2 {
		return m[1]
	}
	// Fallback: try a tolerant JSON unmarshal — handles cases where the
	// token is in a nested "data" envelope.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err == nil {
		if v, ok := parsed["token"].(string); ok && v != "" {
			return v
		}
		if v, ok := parsed["reset_token"].(string); ok && v != "" {
			return v
		}
		if data, ok := parsed["data"].(map[string]any); ok {
			if v, ok := data["token"].(string); ok && v != "" {
				return v
			}
		}
	}
	return ""
}

// buildRequestBody / buildConfirmBody build JSON payloads small enough
// to flex multiple shapes — the regex / matcher on the server side
// usually finds the field it cares about.
func buildRequestBody(user string) string {
	if user == "" {
		user = "anonymous@example.com"
	}
	out, _ := json.Marshal(map[string]string{
		"email":    user,
		"username": user,
	})
	return string(out)
}

func buildConfirmBody(user, token, newPassword string) string {
	if user == "" {
		user = "anonymous@example.com"
	}
	out, _ := json.Marshal(map[string]string{
		"email":        user,
		"username":     user,
		"token":        token,
		"reset_token":  token,
		"new_password": newPassword,
		"password":     newPassword,
	})
	return string(out)
}

// chooseConfirmURL picks a confirm URL based on the request URL when
// available. We try a few common sibling paths; the first that contains
// the canonical "confirm" / "reset" segment wins. This keeps the
// detector robust against routes that don't share a base path.
func chooseConfirmURL(resetURL, requestURL string) string {
	// If the request URL already contains "confirm", reuse it.
	for _, hint := range confirmPathHints {
		if hint != "" && strings.Contains(strings.ToLower(requestURL), strings.ToLower(hint)) {
			return requestURL
		}
	}
	for _, hint := range confirmPathHints {
		if hint == "" {
			continue
		}
		candidate := joinPath(resetURL, hint)
		if candidate != requestURL {
			return candidate
		}
	}
	return resetURL
}

// joinPath concatenates a base URL with a path hint. It is intentionally
// dumb — we don't want url.Parse normalization to drop trailing slashes
// or rewrite test-server URLs.
func joinPath(base, hint string) string {
	if hint == "" {
		return base
	}
	base = strings.TrimRight(base, "/")
	hint = strings.TrimLeft(hint, "/")
	return base + "/" + hint
}

// looksLikeConfirmSuccess is the heuristic used to decide whether a
// confirm POST succeeded. We prefer explicit 2xx status codes; for 200
// we also require the body not to mention error / invalid / forbidden.
// 4xx / 5xx is always failure.
func looksLikeConfirmSuccess(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode >= 400 {
		return false
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		lower := strings.ToLower(resp.Body)
		failureMarkers := []string{
			"invalid token",
			"invalid_token",
			"token expired",
			"token_expired",
			"already used",
			"forbidden",
			"unauthorized",
			"\"error\"",
			"not allowed",
		}
		for _, m := range failureMarkers {
			if strings.Contains(lower, m) {
				return false
			}
		}
		return true
	}
	// 3xx redirects: treat as success only if Location is set — many
	// reset flows redirect to /login or /done on success.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.Headers["Location"] != ""
	}
	return false
}

// containsAttacker checks whether the attacker host appears in the
// response body or in any link-building response header. We deliberately
// look at headers (Location / Link) AND body — reset-link APIs return
// the URL in JSON, while form-based flows hand it back via Location.
func containsAttacker(resp *http.Response, attacker string) bool {
	if resp == nil {
		return false
	}
	atk := strings.ToLower(attacker)
	for _, hdr := range []string{"Location", "Link", "Refresh", "Content-Location"} {
		if v := resp.Headers[hdr]; v != "" && strings.Contains(strings.ToLower(v), atk) {
			return true
		}
	}
	return strings.Contains(strings.ToLower(resp.Body), atk)
}

// truncate cuts a string to at most n bytes for inclusion in evidence
// (avoids dumping multi-megabyte bodies into the finding).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
