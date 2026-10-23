package iast

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"
)

func TestMarkerRoundTrip(t *testing.T) {
	id, payload := GenerateMarker(SinkSQLQuery)
	if id == "" {
		t.Fatal("id is empty")
	}
	if !IsMarker(payload) {
		t.Fatalf("IsMarker(%q) = false", payload)
	}
	got := ExtractMarkerID(payload)
	if got != id {
		t.Fatalf("ExtractMarkerID = %q, want %q", got, id)
	}
}

func TestWrapPayload(t *testing.T) {
	wrapped := WrapPayload("' OR 1=1 --", "abcd1234", SinkSQLQuery)
	if !IsMarker(wrapped) {
		t.Fatal("wrapped payload not detected as marker")
	}
	if ExtractMarkerID(wrapped) != "abcd1234" {
		t.Fatal("marker ID mismatch")
	}
}

func TestServerAcceptsSinkHit(t *testing.T) {
	srv := NewServer(":0") // OS-assigned port
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	// Wait for server to start.
	time.Sleep(100 * time.Millisecond)

	// The server listens on :0 so we need to find the actual port.
	// Since our Server.Start uses net.Listen then Serve, the addr is
	// resolved. We'll post to localhost:7880 if we used a fixed port,
	// but with :0 we need a workaround. Let's use a fixed high port.
	cancel()
	<-errCh

	// Re-test with a fixed port
	srv2 := NewServer(":17880")
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()

	go func() { srv2.Start(ctx2) }()
	time.Sleep(150 * time.Millisecond)

	hit := SinkHit{
		MarkerID:  "aabbccdd",
		SinkType:  SinkSQLQuery,
		SinkValue: "SELECT * FROM users WHERE name='ASSAY_TAINT_aabbccdd_sql_query_' OR 1=1 --_TAINT_ASSAY'",
	}
	body, _ := json.Marshal(hit)

	resp, err := http.Post("http://127.0.0.1:17880/api/v1/sink", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}

	hits := srv2.Hits()
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	if hits[0].MarkerID != "aabbccdd" {
		t.Fatalf("marker_id = %q, want aabbccdd", hits[0].MarkerID)
	}
	if hits[0].SinkType != SinkSQLQuery {
		t.Fatalf("sink_type = %q, want sql_query", hits[0].SinkType)
	}

	cancel2()
}

func TestServerRejectsGET(t *testing.T) {
	srv := NewServer(":17881")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:17881/api/v1/sink")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	cancel()
}

func TestServerRejectsEmptyMarker(t *testing.T) {
	srv := NewServer(":17882")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	hit := SinkHit{SinkType: SinkSQLQuery, SinkValue: "test"}
	body, _ := json.Marshal(hit)

	resp, err := http.Post("http://127.0.0.1:17882/api/v1/sink", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
	cancel()
}

func TestHealthz(t *testing.T) {
	srv := NewServer(":17883")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	resp, err := http.Get("http://127.0.0.1:17883/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	cancel()
}

func TestWaitForHit(t *testing.T) {
	srv := NewServer(":17884")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// Post a hit asynchronously after a short delay.
	go func() {
		time.Sleep(200 * time.Millisecond)
		hit := SinkHit{MarkerID: "deadbeef", SinkType: SinkSysCommand, SinkValue: "id"}
		body, _ := json.Marshal(hit)
		http.Post("http://127.0.0.1:17884/api/v1/sink", "application/json", bytes.NewReader(body))
	}()

	got := srv.WaitForHit("deadbeef", 3*time.Second)
	if got == nil {
		t.Fatal("WaitForHit returned nil (timeout)")
	}
	if got.SinkType != SinkSysCommand {
		t.Fatalf("sink_type = %q, want sys_command", got.SinkType)
	}
	cancel()
}

func TestWaitForHitTimeout(t *testing.T) {
	srv := NewServer(":17885")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	got := srv.WaitForHit("nonexistent", 300*time.Millisecond)
	if got != nil {
		t.Fatal("expected nil on timeout")
	}
	cancel()
}

func TestHitsByMarker(t *testing.T) {
	srv := NewServer(":17886")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { srv.Start(ctx) }()
	time.Sleep(100 * time.Millisecond)

	for i, mid := range []string{"aaaa1111", "bbbb2222", "aaaa1111"} {
		hit := SinkHit{MarkerID: mid, SinkType: SinkSQLQuery, SinkValue: fmt.Sprintf("val%d", i)}
		body, _ := json.Marshal(hit)
		http.Post("http://127.0.0.1:17886/api/v1/sink", "application/json", bytes.NewReader(body))
	}
	time.Sleep(100 * time.Millisecond)

	got := srv.HitsByMarker("aaaa1111")
	if len(got) != 2 {
		t.Fatalf("got %d hits for aaaa1111, want 2", len(got))
	}
	cancel()
}
