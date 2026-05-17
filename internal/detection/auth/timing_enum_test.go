package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	skwshttp "github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

func TestDetectTimingEnumeration_VulnerableServer(t *testing.T) {
	// Server simulates a vulnerable login: bcrypt-style 60ms hash check
	// only runs when the username exists; invalid users return quickly.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if strings.EqualFold(body.Username, "admin") {
			time.Sleep(60 * time.Millisecond) // hash the candidate password
		}
		// Same generic body — only timing differs
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Invalid credentials"}`))
	}))
	defer server.Close()

	client := skwshttp.NewClient().WithTimeout(15 * time.Second)
	det := New(client)

	opts := TimingEnumOptions{
		ValidUser:   "admin",
		InvalidUser: "nope_xyz_qqq",
		Samples:     8,
		Timeout:     5 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := det.DetectTimingEnumeration(ctx, server.URL, opts)
	if err != nil {
		t.Fatalf("DetectTimingEnumeration: %v", err)
	}
	if !result.Vulnerable {
		t.Fatalf("expected vulnerable=true (60ms vs ~0ms gap), got false. mean_valid=%v mean_invalid=%v",
			result.MeanValid, result.MeanInvalid)
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := result.Findings[0]
	if f.Severity == "" {
		t.Error("expected severity to be set")
	}
	if f.Type != "Account Enumeration via Timing" {
		t.Errorf("unexpected type: %q", f.Type)
	}
}

func TestDetectTimingEnumeration_SafeServer(t *testing.T) {
	// Server processes both valid and invalid users identically.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond) // same path for everyone
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Invalid credentials"}`))
	}))
	defer server.Close()

	client := skwshttp.NewClient().WithTimeout(15 * time.Second)
	det := New(client)

	opts := TimingEnumOptions{
		ValidUser:   "admin",
		InvalidUser: "nope_xyz_qqq",
		Samples:     8,
		Timeout:     5 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := det.DetectTimingEnumeration(ctx, server.URL, opts)
	if err != nil {
		t.Fatalf("DetectTimingEnumeration: %v", err)
	}
	if result.Vulnerable {
		t.Fatalf("expected vulnerable=false (no timing gap), got true. mean_valid=%v mean_invalid=%v",
			result.MeanValid, result.MeanInvalid)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected zero findings, got %d", len(result.Findings))
	}
}

func TestDetectTimingEnumeration_DefaultSamples(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("nope"))
	}))
	defer server.Close()

	client := skwshttp.NewClient().WithTimeout(5 * time.Second)
	det := New(client)

	opts := TimingEnumOptions{ValidUser: "u1", InvalidUser: "u2"} // Samples=0 → default
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := det.DetectTimingEnumeration(ctx, server.URL, opts)
	if err != nil {
		t.Fatalf("DetectTimingEnumeration: %v", err)
	}
	if result.SamplesTaken < 5 {
		t.Errorf("expected default to be >=5 samples, got %d", result.SamplesTaken)
	}
}
