package iast

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
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

func TestExtractMarkerID_NoMarker(t *testing.T) {
	if id := ExtractMarkerID("no marker here"); id != "" {
		t.Fatalf("expected empty, got %q", id)
	}
}

func startTestServer(t *testing.T) (*Server, string, context.CancelFunc) {
	t.Helper()
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	srv := NewServer(addr)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { srv.Start(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return srv, "http://" + addr, cancel
}

func TestServerAcceptsSinkHit(t *testing.T) {
	srv, base, cancel := startTestServer(t)
	defer cancel()

	hit := SinkHit{MarkerID: "aabbccdd", SinkType: SinkSQLQuery, SinkValue: "test"}
	body, _ := json.Marshal(hit)
	resp, err := http.Post(base+"/api/v1/sink", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	hits := srv.Hits()
	if len(hits) != 1 {
		t.Fatalf("got %d hits, want 1", len(hits))
	}
	if hits[0].MarkerID != "aabbccdd" {
		t.Fatalf("marker_id = %q, want aabbccdd", hits[0].MarkerID)
	}
}

func TestServerRejectsGET(t *testing.T) {
	_, base, cancel := startTestServer(t)
	defer cancel()
	resp, err := http.Get(base + "/api/v1/sink")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestServerRejectsEmptyMarker(t *testing.T) {
	_, base, cancel := startTestServer(t)
	defer cancel()
	hit := SinkHit{SinkType: SinkSQLQuery, SinkValue: "test"}
	body, _ := json.Marshal(hit)
	resp, err := http.Post(base+"/api/v1/sink", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", resp.StatusCode)
	}
}

func TestHealthz(t *testing.T) {
	_, base, cancel := startTestServer(t)
	defer cancel()
	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestWaitForHit(t *testing.T) {
	srv, base, cancel := startTestServer(t)
	defer cancel()
	go func() {
		time.Sleep(200 * time.Millisecond)
		hit := SinkHit{MarkerID: "deadbeef", SinkType: SinkSysCommand, SinkValue: "id"}
		body, _ := json.Marshal(hit)
		http.Post(base+"/api/v1/sink", "application/json", bytes.NewReader(body))
	}()
	got := srv.WaitForHit("deadbeef", 3*time.Second)
	if got == nil {
		t.Fatal("WaitForHit returned nil (timeout)")
	}
	if got.SinkType != SinkSysCommand {
		t.Fatalf("sink_type = %q, want sys_command", got.SinkType)
	}
}

func TestWaitForHitTimeout(t *testing.T) {
	srv, _, cancel := startTestServer(t)
	defer cancel()
	got := srv.WaitForHit("nonexistent", 300*time.Millisecond)
	if got != nil {
		t.Fatal("expected nil on timeout")
	}
}

func TestHitsByMarker(t *testing.T) {
	srv, base, cancel := startTestServer(t)
	defer cancel()
	for i, mid := range []string{"aaaa1111", "bbbb2222", "aaaa1111"} {
		hit := SinkHit{MarkerID: mid, SinkType: SinkSQLQuery, SinkValue: fmt.Sprintf("val%d", i)}
		body, _ := json.Marshal(hit)
		http.Post(base+"/api/v1/sink", "application/json", bytes.NewReader(body))
	}
	time.Sleep(100 * time.Millisecond)
	got := srv.HitsByMarker("aaaa1111")
	if len(got) != 2 {
		t.Fatalf("got %d hits for aaaa1111, want 2", len(got))
	}
}
