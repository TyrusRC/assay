package analysis

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	skwshttp "github.com/swiss-knife-for-web-security/skws/internal/http"
)

func TestNewTimingAnalyzer(t *testing.T) {
	ta := NewTimingAnalyzer()
	if ta == nil {
		t.Fatal("NewTimingAnalyzer() returned nil")
	}
	if ta.baselineSamples != 5 {
		t.Errorf("baselineSamples = %d, want 5", ta.baselineSamples)
	}
	if ta.confirmationRounds != 3 {
		t.Errorf("confirmationRounds = %d, want 3", ta.confirmationRounds)
	}
	if ta.requiredConfirms != 2 {
		t.Errorf("requiredConfirms = %d, want 2", ta.requiredConfirms)
	}
}

func TestTimingAnalyzer_Analyze_DelayDetected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	// Server delays for 500ms when the delay payload is received.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if param == "1; WAITFOR DELAY '00:00:01'" {
			time.Sleep(500 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := skwshttp.NewClient()
	ta := NewTimingAnalyzer()

	result := ta.Analyze(
		context.Background(),
		client,
		server.URL+"?id=1",
		"id",
		"GET",
		"1; WAITFOR DELAY '00:00:01'",
		500*time.Millisecond,
	)

	if result == nil {
		t.Fatal("Analyze() returned nil")
	}
	if !result.IsDelayed {
		t.Error("IsDelayed should be true when server delays on payload")
	}
	if result.Confidence <= 0 {
		t.Errorf("Confidence = %f, want > 0", result.Confidence)
	}
	if result.BaselineMean <= 0 {
		t.Errorf("BaselineMean = %v, want > 0", result.BaselineMean)
	}
	if result.MeasuredDelay <= 0 {
		t.Errorf("MeasuredDelay = %v, want > 0", result.MeasuredDelay)
	}
}

func TestTimingAnalyzer_Analyze_NoDelay(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	// Server never delays regardless of payload.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := skwshttp.NewClient()
	ta := NewTimingAnalyzer()

	result := ta.Analyze(
		context.Background(),
		client,
		server.URL+"?id=1",
		"id",
		"GET",
		"1; WAITFOR DELAY '00:00:05'",
		5*time.Second,
	)

	if result == nil {
		t.Fatal("Analyze() returned nil")
	}
	if result.IsDelayed {
		t.Error("IsDelayed should be false when server does not delay")
	}
	if result.BaselineMean <= 0 {
		t.Errorf("BaselineMean = %v, want > 0", result.BaselineMean)
	}
}

func TestTimingAnalyzer_Analyze_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := skwshttp.NewClient()
	ta := NewTimingAnalyzer()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := ta.Analyze(
		ctx,
		client,
		server.URL+"?id=1",
		"id",
		"GET",
		"delay_payload",
		5*time.Second,
	)

	if result == nil {
		t.Fatal("Analyze() returned nil on cancelled context")
	}
	if result.IsDelayed {
		t.Error("IsDelayed should be false when context is cancelled")
	}
}

func TestTimingResult_Fields(t *testing.T) {
	result := &TimingResult{
		IsDelayed:      true,
		Confidence:     0.85,
		BaselineMean:   50 * time.Millisecond,
		BaselineStdDev: 10 * time.Millisecond,
		MeasuredDelay:  5 * time.Second,
	}

	if !result.IsDelayed {
		t.Error("IsDelayed should be true")
	}
	if result.Confidence != 0.85 {
		t.Errorf("Confidence = %f, want 0.85", result.Confidence)
	}
	if result.BaselineMean != 50*time.Millisecond {
		t.Errorf("BaselineMean = %v", result.BaselineMean)
	}
	if result.BaselineStdDev != 10*time.Millisecond {
		t.Errorf("BaselineStdDev = %v", result.BaselineStdDev)
	}
	if result.MeasuredDelay != 5*time.Second {
		t.Errorf("MeasuredDelay = %v", result.MeasuredDelay)
	}
}

func TestCalculateBaselineStats(t *testing.T) {
	tests := []struct {
		name       string
		durations  []time.Duration
		wantMean   time.Duration
		wantStdDev time.Duration
		tolerance  time.Duration
	}{
		{
			name: "uniform durations",
			durations: []time.Duration{
				100 * time.Millisecond,
				100 * time.Millisecond,
				100 * time.Millisecond,
				100 * time.Millisecond,
				100 * time.Millisecond,
			},
			wantMean:   100 * time.Millisecond,
			wantStdDev: 0,
			tolerance:  1 * time.Millisecond,
		},
		{
			name: "varied durations",
			durations: []time.Duration{
				10 * time.Millisecond,
				20 * time.Millisecond,
				30 * time.Millisecond,
				40 * time.Millisecond,
				50 * time.Millisecond,
			},
			wantMean:   30 * time.Millisecond,
			wantStdDev: 14142135 * time.Nanosecond, // sqrt(200000000) ~= 14142135ns
			tolerance:  2 * time.Millisecond,
		},
		{
			name:       "empty durations",
			durations:  []time.Duration{},
			wantMean:   0,
			wantStdDev: 0,
			tolerance:  0,
		},
		{
			name: "single duration",
			durations: []time.Duration{
				50 * time.Millisecond,
			},
			wantMean:   50 * time.Millisecond,
			wantStdDev: 0,
			tolerance:  1 * time.Millisecond,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mean, stddev := calculateBaselineStats(tt.durations)

			meanDiff := absDuration(mean - tt.wantMean)
			if meanDiff > tt.tolerance {
				t.Errorf("mean = %v, want %v (tolerance %v)", mean, tt.wantMean, tt.tolerance)
			}

			stddevDiff := absDuration(stddev - tt.wantStdDev)
			if stddevDiff > tt.tolerance {
				t.Errorf("stddev = %v, want %v (tolerance %v)", stddev, tt.wantStdDev, tt.tolerance)
			}
		})
	}
}

func TestTimingAnalyzer_Analyze_ShortDelay(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	// Server adds a 200ms delay when the specific payload is used.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("q")
		if param == "sleep_payload" {
			time.Sleep(200 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := skwshttp.NewClient()
	ta := NewTimingAnalyzer()

	result := ta.Analyze(
		context.Background(),
		client,
		server.URL+"?q=normal",
		"q",
		"GET",
		"sleep_payload",
		200*time.Millisecond,
	)

	if result == nil {
		t.Fatal("Analyze() returned nil")
	}
	if !result.IsDelayed {
		t.Error("IsDelayed should be true for 200ms delay")
	}
}

// absDuration returns the absolute value of a duration.
func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func TestAbsDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want time.Duration
	}{
		{"positive", 5 * time.Second, 5 * time.Second},
		{"negative", -5 * time.Second, 5 * time.Second},
		{"zero", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := absDuration(tt.d)
			if got != tt.want {
				t.Errorf("absDuration(%v) = %v, want %v", tt.d, got, tt.want)
			}
		})
	}
}

// TestTimingAnalyzer_Analyze_ContextTimeout verifies the analyzer respects
// context deadlines and returns gracefully.
func TestTimingAnalyzer_Analyze_ContextTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	client := skwshttp.NewClient()
	ta := NewTimingAnalyzer()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Give time for the deadline to pass.
	time.Sleep(5 * time.Millisecond)

	result := ta.Analyze(
		ctx,
		client,
		server.URL+"?id=1",
		"id",
		"GET",
		"delay_payload",
		5*time.Second,
	)

	if result == nil {
		t.Fatal("Analyze() returned nil on timed-out context")
	}
	if result.IsDelayed {
		t.Error("IsDelayed should be false when context is timed out")
	}
}

// Ensure math import is used.
var _ = math.Sqrt
