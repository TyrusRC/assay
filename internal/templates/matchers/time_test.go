package matchers

import (
	"testing"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/templates"
)

func TestMatchTime_GreaterThan(t *testing.T) {
	e := New()

	tests := []struct {
		name        string
		duration    time.Duration
		baseline    time.Duration
		operator    string
		expectMatch bool
	}{
		{
			name:        "Greater than - match",
			duration:    5 * time.Second,
			baseline:    2 * time.Second,
			operator:    ">",
			expectMatch: true,
		},
		{
			name:        "Greater than - no match",
			duration:    1 * time.Second,
			baseline:    2 * time.Second,
			operator:    ">",
			expectMatch: false,
		},
		{
			name:        "Greater than - equal no match",
			duration:    2 * time.Second,
			baseline:    2 * time.Second,
			operator:    ">",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{
				Duration: tt.duration,
			}
			data := map[string]interface{}{
				"baseline_duration": tt.baseline,
			}
			matcher := &templates.Matcher{
				Type: "time",
				DSL:  []string{tt.operator + " " + tt.baseline.String()},
			}
			result := e.Match(matcher, resp, data)
			if result.Matched != tt.expectMatch {
				t.Errorf("matchTime() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatchTime_LessThan(t *testing.T) {
	e := New()

	tests := []struct {
		name        string
		duration    time.Duration
		baseline    time.Duration
		operator    string
		expectMatch bool
	}{
		{
			name:        "Less than - match",
			duration:    1 * time.Second,
			baseline:    2 * time.Second,
			operator:    "<",
			expectMatch: true,
		},
		{
			name:        "Less than - no match",
			duration:    5 * time.Second,
			baseline:    2 * time.Second,
			operator:    "<",
			expectMatch: false,
		},
		{
			name:        "Less than - equal no match",
			duration:    2 * time.Second,
			baseline:    2 * time.Second,
			operator:    "<",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{
				Duration: tt.duration,
			}
			data := map[string]interface{}{
				"baseline_duration": tt.baseline,
			}
			matcher := &templates.Matcher{
				Type: "time",
				DSL:  []string{tt.operator + " " + tt.baseline.String()},
			}
			result := e.Match(matcher, resp, data)
			if result.Matched != tt.expectMatch {
				t.Errorf("matchTime() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatchTime_GreaterThanOrEqual(t *testing.T) {
	e := New()

	tests := []struct {
		name        string
		duration    time.Duration
		baseline    time.Duration
		operator    string
		expectMatch bool
	}{
		{
			name:        "Greater than or equal - greater",
			duration:    5 * time.Second,
			baseline:    2 * time.Second,
			operator:    ">=",
			expectMatch: true,
		},
		{
			name:        "Greater than or equal - equal",
			duration:    2 * time.Second,
			baseline:    2 * time.Second,
			operator:    ">=",
			expectMatch: true,
		},
		{
			name:        "Greater than or equal - less",
			duration:    1 * time.Second,
			baseline:    2 * time.Second,
			operator:    ">=",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{
				Duration: tt.duration,
			}
			data := map[string]interface{}{
				"baseline_duration": tt.baseline,
			}
			matcher := &templates.Matcher{
				Type: "time",
				DSL:  []string{tt.operator + " " + tt.baseline.String()},
			}
			result := e.Match(matcher, resp, data)
			if result.Matched != tt.expectMatch {
				t.Errorf("matchTime() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatchTime_LessThanOrEqual(t *testing.T) {
	e := New()

	tests := []struct {
		name        string
		duration    time.Duration
		baseline    time.Duration
		operator    string
		expectMatch bool
	}{
		{
			name:        "Less than or equal - less",
			duration:    1 * time.Second,
			baseline:    2 * time.Second,
			operator:    "<=",
			expectMatch: true,
		},
		{
			name:        "Less than or equal - equal",
			duration:    2 * time.Second,
			baseline:    2 * time.Second,
			operator:    "<=",
			expectMatch: true,
		},
		{
			name:        "Less than or equal - greater",
			duration:    5 * time.Second,
			baseline:    2 * time.Second,
			operator:    "<=",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{
				Duration: tt.duration,
			}
			data := map[string]interface{}{
				"baseline_duration": tt.baseline,
			}
			matcher := &templates.Matcher{
				Type: "time",
				DSL:  []string{tt.operator + " " + tt.baseline.String()},
			}
			result := e.Match(matcher, resp, data)
			if result.Matched != tt.expectMatch {
				t.Errorf("matchTime() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatchTime_Equal(t *testing.T) {
	e := New()

	tests := []struct {
		name        string
		duration    time.Duration
		baseline    time.Duration
		operator    string
		tolerance   time.Duration
		expectMatch bool
	}{
		{
			name:        "Equal - exact match",
			duration:    2 * time.Second,
			baseline:    2 * time.Second,
			operator:    "==",
			tolerance:   100 * time.Millisecond,
			expectMatch: true,
		},
		{
			name:        "Equal - within tolerance",
			duration:    2*time.Second + 50*time.Millisecond,
			baseline:    2 * time.Second,
			operator:    "==",
			tolerance:   100 * time.Millisecond,
			expectMatch: true,
		},
		{
			name:        "Equal - outside tolerance",
			duration:    3 * time.Second,
			baseline:    2 * time.Second,
			operator:    "==",
			tolerance:   100 * time.Millisecond,
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &Response{
				Duration: tt.duration,
			}
			data := map[string]interface{}{
				"baseline_duration": tt.baseline,
				"time_tolerance":    tt.tolerance,
			}
			matcher := &templates.Matcher{
				Type: "time",
				DSL:  []string{tt.operator + " " + tt.baseline.String()},
			}
			result := e.Match(matcher, resp, data)
			if result.Matched != tt.expectMatch {
				t.Errorf("matchTime() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}

func TestMatchTime_WithMultiplier(t *testing.T) {
	e := New()

	// Test time-based SQL injection detection pattern:
	// Response time should be >= baseline * multiplier
	resp := &Response{
		Duration: 10 * time.Second,
	}
	data := map[string]interface{}{
		"baseline_duration": 2 * time.Second,
		"time_multiplier":   float64(3), // Expect at least 6 seconds
	}
	matcher := &templates.Matcher{
		Type: "time",
		DSL:  []string{">= baseline * 3"},
	}
	result := e.Match(matcher, resp, data)
	if !result.Matched {
		t.Error("matchTime() should match when duration >= baseline * multiplier")
	}
}

func TestMatchTime_Negative(t *testing.T) {
	e := New()

	resp := &Response{
		Duration: 5 * time.Second,
	}
	data := map[string]interface{}{
		"baseline_duration": 2 * time.Second,
	}
	matcher := &templates.Matcher{
		Type:     "time",
		DSL:      []string{"> 2s"},
		Negative: true,
	}
	result := e.Match(matcher, resp, data)
	if result.Matched {
		t.Error("Negative time matcher should not match when condition is true")
	}
}

func TestMatchTime_Condition(t *testing.T) {
	e := New()

	resp := &Response{
		Duration: 5 * time.Second,
	}

	tests := []struct {
		name        string
		dsl         []string
		condition   string
		expectMatch bool
	}{
		{
			name:        "OR condition - one matches",
			dsl:         []string{"> 10s", "> 3s"},
			condition:   "or",
			expectMatch: true,
		},
		{
			name:        "AND condition - all match",
			dsl:         []string{"> 3s", "< 10s"},
			condition:   "and",
			expectMatch: true,
		},
		{
			name:        "AND condition - one fails",
			dsl:         []string{"> 3s", "> 10s"},
			condition:   "and",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matcher := &templates.Matcher{
				Type:      "time",
				DSL:       tt.dsl,
				Condition: tt.condition,
			}
			result := e.Match(matcher, resp, nil)
			if result.Matched != tt.expectMatch {
				t.Errorf("matchTime() = %v, want %v", result.Matched, tt.expectMatch)
			}
		})
	}
}
