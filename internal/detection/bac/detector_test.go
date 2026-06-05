package bac

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	httpx "github.com/TyrusRC/assay/internal/http"
)

const secretBody = "TOP SECRET account balance and personal data for the legitimate owner only ............"

func write(w http.ResponseWriter, body string) {
	if _, err := w.Write([]byte(body)); err != nil {
		panic(err)
	}
}

func bacTestServer() *httptest.Server {
	mux := http.NewServeMux()
	// Missing authorization: serves the same privileged content to everyone.
	mux.HandleFunc("/admin/report", func(w http.ResponseWriter, _ *http.Request) {
		write(w, secretBody)
	})
	// Properly protected: requires the privileged session cookie.
	mux.HandleFunc("/proper", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil && c.Value == "a" {
			write(w, secretBody)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		write(w, "forbidden")
	})
	return httptest.NewServer(mux)
}

func newDetector() *Detector {
	priv := Principal{Name: "user-a", Client: httpx.NewClient().WithCookies("session=a")}
	anon := Principal{Name: "anonymous", Client: httpx.NewClient()}
	return New(priv, anon)
}

func TestDetect_FlagsMissingAuthorization(t *testing.T) {
	srv := bacTestServer()
	defer srv.Close()

	d := newDetector()
	findings := d.Detect(context.Background(), []string{srv.URL + "/admin/report"})
	if len(findings) != 1 {
		t.Fatalf("expected 1 BAC finding, got %d", len(findings))
	}
	if !strings.Contains(strings.ToLower(findings[0].Description), "anonymous") {
		t.Errorf("expected anonymous-access detail, got: %s", findings[0].Description)
	}
}

func TestDetect_DoesNotFlagProtected(t *testing.T) {
	srv := bacTestServer()
	defer srv.Close()

	d := newDetector()
	findings := d.Detect(context.Background(), []string{srv.URL + "/proper"})
	if len(findings) != 0 {
		t.Fatalf("properly protected endpoint must not be flagged, got %d: %+v", len(findings), findings)
	}
}

func TestDetect_CrossUser(t *testing.T) {
	srv := bacTestServer()
	defer srv.Close()

	// Two authenticated users, both of whom can read /admin/report (no authz):
	// this is cross-user access, not anonymous.
	priv := Principal{Name: "user-a", Client: httpx.NewClient().WithCookies("session=a")}
	userB := Principal{Name: "user-b", Client: httpx.NewClient().WithCookies("session=b")}
	d := New(priv, userB)

	findings := d.Detect(context.Background(), []string{srv.URL + "/admin/report"})
	if len(findings) != 1 {
		t.Fatalf("expected 1 cross-user finding, got %d", len(findings))
	}
}

func TestDetect_EmptyEndpoints(t *testing.T) {
	d := newDetector()
	if got := d.Detect(context.Background(), nil); len(got) != 0 {
		t.Fatalf("no endpoints should yield no findings, got %d", len(got))
	}
}

func TestDetect_NoOtherPrincipalsSafe(t *testing.T) {
	srv := bacTestServer()
	defer srv.Close()
	// With no comparison principals there is nothing to differentiate against.
	d := New(Principal{Name: "user-a", Client: httpx.NewClient().WithCookies("session=a")})
	if got := d.Detect(context.Background(), []string{srv.URL + "/admin/report"}); len(got) != 0 {
		t.Fatalf("no other principals → no findings, got %d", len(got))
	}
}
