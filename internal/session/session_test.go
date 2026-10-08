package session

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	assayhttp "github.com/TyrusRC/assay/internal/http"
)

func TestSession_CookieAndReauth(t *testing.T) {
	var n int32
	reauth := func(ctx context.Context) (string, error) {
		atomic.AddInt32(&n, 1)
		return "session=fresh", nil
	}
	s := New("session=old", reauth, "", "")
	if s.Cookie() != "session=old" {
		t.Fatalf("initial cookie = %q", s.Cookie())
	}
	if _, err := s.Reauth(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Cookie() != "session=fresh" {
		t.Errorf("post-reauth cookie = %q, want session=fresh", s.Cookie())
	}
	if s.Reauths() != 1 {
		t.Errorf("reauths = %d, want 1", s.Reauths())
	}
}

func TestSession_AliveMarker(t *testing.T) {
	loggedOut := int32(0)
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if atomic.LoadInt32(&loggedOut) == 1 {
			w.Write([]byte("Please log in"))
			return
		}
		w.Write([]byte("Welcome, wiener. Dashboard"))
	}))
	defer srv.Close()

	s := New("c=1", nil, srv.URL, "Dashboard")
	client := assayhttp.NewClient()
	if !s.Alive(context.Background(), client) {
		t.Error("marker present -> session must be alive")
	}
	atomic.StoreInt32(&loggedOut, 1)
	if s.Alive(context.Background(), client) {
		t.Error("marker gone -> session must be detected logged out")
	}
}

func TestSession_Alive401IsLogout(t *testing.T) {
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(nethttp.StatusUnauthorized)
	}))
	defer srv.Close()
	s := New("c=1", nil, srv.URL, "")
	if s.Alive(context.Background(), assayhttp.NewClient()) {
		t.Error("401 canary -> session must be logged out")
	}
}

func TestSession_KeepaliveReauthsOnLogout(t *testing.T) {
	var loggedOut, reauthed int32
	srv := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		if atomic.LoadInt32(&loggedOut) == 1 {
			w.WriteHeader(nethttp.StatusUnauthorized)
			return
		}
		w.Write([]byte("ok authed"))
	}))
	defer srv.Close()

	reauth := func(ctx context.Context) (string, error) {
		atomic.StoreInt32(&reauthed, 1)
		atomic.StoreInt32(&loggedOut, 0) // the re-login restores the session
		return "c=new", nil
	}
	s := New("c=1", reauth, srv.URL, "authed")
	atomic.StoreInt32(&loggedOut, 1)

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	s.Keepalive(ctx, assayhttp.NewClient(), 30*time.Millisecond, nil)

	if atomic.LoadInt32(&reauthed) != 1 {
		t.Error("keepalive must re-authenticate after detecting logout")
	}
	if s.Reauths() == 0 {
		t.Error("reauth count must advance")
	}
}
