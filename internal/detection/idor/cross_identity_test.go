package idor

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// twoUserApp simulates a multi-user resource server. Each user has a
// session cookie and a private record. The vulnerable variant returns
// any user's record to anyone holding ANY valid session — the canonical
// IDOR. The safe variant scopes the response to the session's own user.
type twoUserApp struct {
	mu       sync.Mutex
	users    map[string]string // sessionCookie -> userID
	records  map[string]string // userID -> private body
	scoping  bool              // true = safe (responds with session user's data); false = vulnerable (responds with whatever ID is in URL)
}

func newTwoUserApp(scoping bool) *twoUserApp {
	return &twoUserApp{
		users: map[string]string{
			"alice-session": "alice",
			"bob-session":   "bob",
		},
		records: map[string]string{
			"alice": `{"user":"alice@example.com","ssn":"123-45-6789","balance":4231.07,"orders":[{"id":1,"item":"book","ship_to":"742 Evergreen St"}]}`,
			"bob":   `{"user":"bob@example.com","ssn":"987-65-4321","balance":91.50,"orders":[{"id":99,"item":"shoes","ship_to":"800 Brick Ln"}]}`,
		},
		scoping: scoping,
	}
}

func (a *twoUserApp) handle(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("session")
	if c == nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("login required"))
		return
	}
	a.mu.Lock()
	sessionUser, ok := a.users[c.Value]
	a.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("invalid session"))
		return
	}

	// Path: /api/users/<id>/profile
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "api" || parts[1] != "users" || parts[3] != "profile" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	requestedUser := parts[2]

	if a.scoping {
		// Safe: regardless of what the URL says, return the session user's data.
		// This is the correct behavior — auth is derived from session, not URL.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(a.records[sessionUser]))
		return
	}

	// Vulnerable: return whatever user the URL asks for, regardless of session owner.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(a.records[requestedUser]))
}

// TestDetectCrossIdentity_VulnerableServer_FlagsCritical: the textbook
// IDOR. Bob's session reads alice's private record; the response contains
// alice's PII (ssn, email). Detector should flag Critical.
func TestDetectCrossIdentity_VulnerableServer_FlagsCritical(t *testing.T) {
	app := newTwoUserApp(false) // vulnerable
	srv := httptest.NewServer(http.HandlerFunc(app.handle))
	defer srv.Close()

	victim := internalhttp.NewClient().WithCookies("session=alice-session").WithFollowRedirects(false)
	attacker := internalhttp.NewClient().WithCookies("session=bob-session").WithFollowRedirects(false)
	d := New(internalhttp.NewClient())

	target := srv.URL + "/api/users/alice/profile" // alice's resource
	res, err := d.DetectCrossIdentity(context.Background(), target, victim, attacker, DefaultCrossIdentityOptions())
	if err != nil {
		t.Fatalf("DetectCrossIdentity: %v", err)
	}
	if !res.Vulnerable {
		t.Fatalf("expected IDOR finding; got %+v", res.Findings)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := res.Findings[0]
	if f.Severity != core.SeverityCritical {
		t.Errorf("body contains SSN + email — expected Critical; got %s", f.Severity)
	}
	if !strings.Contains(f.Description, "matches the victim's") {
		t.Errorf("description should explain the cross-identity match; got %q", f.Description)
	}
	apiHit := false
	for _, t10 := range f.APITop10 {
		if t10 == "API1:2023" {
			apiHit = true
			break
		}
	}
	if !apiHit {
		t.Errorf("finding should map to API1:2023 BOLA")
	}
}

// TestDetectCrossIdentity_SafeServer_NoFinding: the FP guard. A correctly-
// scoped server returns the SESSION user's data regardless of URL. Bob
// hits alice's URL → gets bob's data. Bodies don't match → no finding.
func TestDetectCrossIdentity_SafeServer_NoFinding(t *testing.T) {
	app := newTwoUserApp(true) // safe / scoping
	srv := httptest.NewServer(http.HandlerFunc(app.handle))
	defer srv.Close()

	victim := internalhttp.NewClient().WithCookies("session=alice-session").WithFollowRedirects(false)
	attacker := internalhttp.NewClient().WithCookies("session=bob-session").WithFollowRedirects(false)
	d := New(internalhttp.NewClient())

	target := srv.URL + "/api/users/alice/profile"
	res, err := d.DetectCrossIdentity(context.Background(), target, victim, attacker, DefaultCrossIdentityOptions())
	if err != nil {
		t.Fatalf("DetectCrossIdentity: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("safe server must not trip; got %+v", res.Findings)
	}
}

// TestDetectCrossIdentity_AttackerDenied_NoFinding: attacker gets 403
// when probing victim's URL — the server denied access correctly.
func TestDetectCrossIdentity_AttackerDenied_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("session")
		if c == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Determine session user
		sessionUser := ""
		switch c.Value {
		case "alice-session":
			sessionUser = "alice"
		case "bob-session":
			sessionUser = "bob"
		}
		// Path: /api/users/<id>/profile
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if len(parts) < 4 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		requestedUser := parts[2]
		if sessionUser != requestedUser {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte("forbidden"))
			return
		}
		// alice can read alice
		body, _ := json.Marshal(map[string]string{"user": sessionUser, "ssn": "123-45-6789"})
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}))
	defer srv.Close()

	victim := internalhttp.NewClient().WithCookies("session=alice-session").WithFollowRedirects(false)
	attacker := internalhttp.NewClient().WithCookies("session=bob-session").WithFollowRedirects(false)
	d := New(internalhttp.NewClient())

	target := srv.URL + "/api/users/alice/profile"
	res, err := d.DetectCrossIdentity(context.Background(), target, victim, attacker, DefaultCrossIdentityOptions())
	if err != nil {
		t.Fatalf("DetectCrossIdentity: %v", err)
	}
	if res.Vulnerable {
		t.Fatalf("403 from attacker is correct authorization; got %+v", res.Findings)
	}
}

// TestDetectCrossIdentity_VictimCantReadOwnResource_NoFinding: if the
// victim itself can't fetch the target (auth expired, wrong URL, etc.)
// we have no ground truth and must emit no findings.
func TestDetectCrossIdentity_VictimCantReadOwnResource_NoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("oops"))
	}))
	defer srv.Close()

	victim := internalhttp.NewClient().WithCookies("session=alice-session").WithFollowRedirects(false)
	attacker := internalhttp.NewClient().WithCookies("session=bob-session").WithFollowRedirects(false)
	d := New(internalhttp.NewClient())

	res, err := d.DetectCrossIdentity(context.Background(), srv.URL+"/whatever", victim, attacker, DefaultCrossIdentityOptions())
	if err != nil {
		t.Fatalf("DetectCrossIdentity: %v", err)
	}
	if res.Vulnerable {
		t.Errorf("no ground truth → no finding; got %+v", res.Findings)
	}
}

// TestDetectCrossIdentity_HighSeverityWhenNoSensitiveMarkers: a body with
// no SSN/credit-card markers but otherwise IDOR-leaking should be High,
// not Critical. Pins the severity grading.
func TestDetectCrossIdentity_HighSeverityWhenNoSensitiveMarkers(t *testing.T) {
	const body = `{"posts":[{"id":1,"title":"My private draft post"},{"id":2,"title":"Another draft"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("session")
		if c == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Vulnerable: any session reads the same body regardless of URL.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	victim := internalhttp.NewClient().WithCookies("session=alice-session").WithFollowRedirects(false)
	attacker := internalhttp.NewClient().WithCookies("session=bob-session").WithFollowRedirects(false)
	d := New(internalhttp.NewClient())

	res, err := d.DetectCrossIdentity(context.Background(), srv.URL+"/api/posts/drafts", victim, attacker, DefaultCrossIdentityOptions())
	if err != nil {
		t.Fatalf("DetectCrossIdentity: %v", err)
	}
	if !res.Vulnerable || len(res.Findings) == 0 {
		t.Fatal("expected IDOR finding")
	}
	if res.Findings[0].Severity != core.SeverityHigh {
		t.Errorf("body has no PII markers — should be High, got %s", res.Findings[0].Severity)
	}
}

// TestDetectCrossIdentity_NilClientErrors pins the input validation.
func TestDetectCrossIdentity_NilClientErrors(t *testing.T) {
	d := New(internalhttp.NewClient())
	if _, err := d.DetectCrossIdentity(context.Background(), "http://example.com", nil, internalhttp.NewClient(), DefaultCrossIdentityOptions()); err == nil {
		t.Error("nil victim should produce an error")
	}
	if _, err := d.DetectCrossIdentity(context.Background(), "http://example.com", internalhttp.NewClient(), nil, DefaultCrossIdentityOptions()); err == nil {
		t.Error("nil attacker should produce an error")
	}
}

// TestBodyJaccard_TolerantToNonces verifies that the Jaccard primitive
// treats per-request nonces as cosmetic noise and still recognizes two
// renderings of the same content as similar.
func TestBodyJaccard_TolerantToNonces(t *testing.T) {
	a := `{"user":"alice","csrf":"a8f7c","items":[{"id":1,"name":"book"}]}`
	b := `{"user":"alice","csrf":"99zzz","items":[{"id":1,"name":"book"}]}`
	if got := bodyJaccard(a, b); got < 0.85 {
		t.Errorf("nonce-only difference should keep Jaccard >= 0.85; got %.3f", got)
	}
}

// TestBodyJaccard_DistinguishesUsers verifies that two different users'
// dashboards produce a low Jaccard score.
func TestBodyJaccard_DistinguishesUsers(t *testing.T) {
	a := `{"user":"alice","ssn":"123-45-6789","balance":4231.07,"orders":[{"id":1,"item":"book"}]}`
	b := `{"user":"bob","ssn":"987-65-4321","balance":91.50,"orders":[{"id":99,"item":"shoes"}]}`
	got := bodyJaccard(a, b)
	if got >= 0.85 {
		t.Errorf("two distinct user records should not score >= 0.85; got %.3f", got)
	}
}
