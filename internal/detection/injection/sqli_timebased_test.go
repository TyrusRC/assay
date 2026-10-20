package injection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	assayhttp "github.com/TyrusRC/assay/internal/http"
)

func TestSQLiDetector_DetectTimeBased_Delayed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if strings.Contains(q, "SLEEP") || strings.Contains(q, "pg_sleep") || strings.Contains(q, "WAITFOR") {
			time.Sleep(3 * time.Second)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := assayhttp.NewClient()
	det := NewSQLiDetector()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := det.DetectTimeBased(ctx, client, server.URL+"?id=1", "id", "GET")
	if err != nil {
		t.Fatalf("DetectTimeBased() error = %v", err)
	}
	if !res.IsVulnerable {
		t.Error("expected time-based SQLi to be detected on delayed server")
	}
	if res.DetectionType != "time-based" {
		t.Errorf("DetectionType = %q, want time-based", res.DetectionType)
	}
	if res.DelayedTime < 2*time.Second {
		t.Errorf("DelayedTime = %v, expected >= 2s", res.DelayedTime)
	}
}

func TestSQLiDetector_DetectTimeBased_NotVulnerable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := assayhttp.NewClient()
	det := NewSQLiDetector()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := det.DetectTimeBased(ctx, client, server.URL+"?id=1", "id", "GET")
	if err != nil {
		t.Fatalf("DetectTimeBased() error = %v", err)
	}
	if res.IsVulnerable {
		t.Error("expected no time-based SQLi on fast server")
	}
}

func TestSQLiDetector_DetectTimeBased_NilClient(t *testing.T) {
	det := NewSQLiDetector()
	res, err := det.DetectTimeBased(context.Background(), nil, "http://example.com", "id", "GET")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.IsVulnerable {
		t.Error("expected not vulnerable with nil client")
	}
}

func TestSQLiDetector_DetectTimeBasedAt_Delayed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if strings.Contains(q, "SLEEP") || strings.Contains(q, "pg_sleep") || strings.Contains(q, "WAITFOR") {
			time.Sleep(3 * time.Second)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client := assayhttp.NewClient()
	det := NewSQLiDetector()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	send := func(ctx context.Context, payload string) (*assayhttp.Response, error) {
		return client.SendPayload(ctx, server.URL+"?id=1", "id", payload, "GET")
	}

	res, err := det.DetectTimeBasedAt(ctx, client, server.URL+"?id=1", "id", "GET", send)
	if err != nil {
		t.Fatalf("DetectTimeBasedAt() error = %v", err)
	}
	if !res.IsVulnerable {
		t.Error("expected time-based SQLi to be detected via At variant")
	}
}
