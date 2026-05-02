package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
	internalhttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// upgradeHandler returns an httptest server that upgrades any GET to a
// WebSocket connection if accept(r) returns true. acceptOrigin filters by
// the Origin header. echoOnce makes the server reply once with the bytes
// it just received (useful for the reflection test).
func upgradeHandler(t *testing.T, acceptOrigin func(string) bool, anonOK bool, echoOnce bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !anonOK && r.Header.Get("Cookie") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if acceptOrigin != nil && !acceptOrigin(r.Header.Get("Origin")) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer conn.Close()
		if echoOnce {
			data, _, err := wsutil.ReadClientData(conn)
			if err != nil {
				return
			}
			_ = wsutil.WriteServerText(conn, data)
		}
	}))
}

// TestDetector_CSWSH_Detected verifies the CSWSH check fires when the
// server upgrades a handshake from a foreign Origin while still receiving
// the user's session cookie.
func TestDetector_CSWSH_Detected(t *testing.T) {
	server := upgradeHandler(t, func(_ string) bool { return true }, true, false)
	defer server.Close()

	client := internalhttp.NewClient().WithCookies("session=victim")
	d := New(client)

	// Inject the WS endpoint as the only "discovered" URL by passing a
	// page body that mentions it. Easier: pass the ws URL directly via
	// upgradeToWS through a target whose body contains the wss URL.
	target := strings.Replace(server.URL, "http://", "http://", 1)
	res, err := d.Detect(context.Background(), target, DetectOptions{Timeout: 3000_000_000, MaxEndpoints: 4})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "CSWSH") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CSWSH finding; got %d findings: %+v", len(res.Findings), res.Findings)
	}
}

// TestDetector_CSWSH_OriginEnforced verifies NO CSWSH finding when the
// server actually checks Origin.
func TestDetector_CSWSH_OriginEnforced(t *testing.T) {
	server := upgradeHandler(t, func(o string) bool {
		return o == "" || strings.HasPrefix(o, "http://127.0.0.1") || strings.HasPrefix(o, "http://localhost")
	}, true, false)
	defer server.Close()

	client := internalhttp.NewClient().WithCookies("session=victim")
	d := New(client)

	res, err := d.Detect(context.Background(), server.URL, DetectOptions{Timeout: 3000_000_000, MaxEndpoints: 4})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "CSWSH") {
			t.Errorf("unexpected CSWSH finding when Origin is enforced: %+v", f)
		}
	}
}

// TestDetector_AnonymousAccept verifies the missing-auth finding fires
// only when baseline auth was present and the server still upgrades
// without it.
func TestDetector_AnonymousAccept(t *testing.T) {
	server := upgradeHandler(t, nil, true, false)
	defer server.Close()

	client := internalhttp.NewClient().WithCookies("session=victim")
	d := New(client)

	res, err := d.Detect(context.Background(), server.URL, DetectOptions{Timeout: 3000_000_000, MaxEndpoints: 4})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "Authentication Bypass") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected anonymous-connect finding; got %+v", res.Findings)
	}
}

// TestDetector_NoBaselineAuth confirms the missing-auth finding does NOT
// fire when the scanner itself has no auth — otherwise every WS endpoint
// would trip it.
func TestDetector_NoBaselineAuth(t *testing.T) {
	server := upgradeHandler(t, nil, true, false)
	defer server.Close()

	client := internalhttp.NewClient() // no cookies
	d := New(client)

	res, err := d.Detect(context.Background(), server.URL, DetectOptions{Timeout: 3000_000_000, MaxEndpoints: 4})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "Authentication Bypass") {
			t.Errorf("unexpected anonymous-connect finding when no baseline auth: %+v", f)
		}
	}
}

// TestDetector_MessageReflection verifies the reflection finding fires
// when the server echoes a sentinel verbatim.
func TestDetector_MessageReflection(t *testing.T) {
	server := upgradeHandler(t, nil, true, true) // echoes once
	defer server.Close()

	client := internalhttp.NewClient()
	d := New(client)

	res, err := d.Detect(context.Background(), server.URL, DetectOptions{Timeout: 3000_000_000, MaxEndpoints: 4})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Type, "Reflection") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected reflection finding; got %+v", res.Findings)
	}
}
