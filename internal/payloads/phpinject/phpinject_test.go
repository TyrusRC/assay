package phpinject

import (
	"strings"
	"testing"
)

func TestGetPayloads_MinCount(t *testing.T) {
	got := GetPayloads()
	if len(got) < 15 {
		t.Errorf("expected at least 15 PHP-sink payloads, got %d", len(got))
	}
}

func TestGetPayloads_Shape(t *testing.T) {
	got := GetPayloads()
	validSink := map[Sink]bool{
		SinkExtract:     true,
		SinkAssert:      true,
		SinkPregReplace: true,
		SinkCallUserFunc: true,
		SinkCreateFunction: true,
		SinkInclude:     true,
		SinkUnsafeUnser: true,
		SinkObjectInst:  true,
	}
	for _, p := range got {
		if p.Value == "" {
			t.Errorf("payload has empty Value")
		}
		if !validSink[p.Sink] {
			t.Errorf("payload %q has invalid Sink %q", p.Value, p.Sink)
		}
	}
}

func TestGetPayloads_CoverSinks(t *testing.T) {
	got := GetPayloads()
	joined := ""
	for _, p := range got {
		joined += p.Value + "\n"
	}
	required := []string{
		"system(",                   // canonical RCE proof
		"phpinfo(",                  // RCE proof via info dump
		"exec(",                     // exec()
		"passthru(",                 // passthru()
		"/e",                        // preg_replace /e modifier
		"php://input",               // include() user-stream chain
		"data://text/plain;base64,", // include() data wrapper
		"O:",                        // PHP serialised object marker
	}
	for _, r := range required {
		if !strings.Contains(joined, r) {
			t.Errorf("PHP-sink bank missing required marker: %q", r)
		}
	}
}

func TestGetBySink_Buckets(t *testing.T) {
	for _, s := range []Sink{SinkExtract, SinkAssert, SinkPregReplace, SinkInclude} {
		got := GetBySink(s)
		if len(got) == 0 {
			t.Errorf("no payloads for sink %q", s)
		}
		for _, p := range got {
			if p.Sink != s {
				t.Errorf("GetBySink(%q) returned %q", s, p.Sink)
			}
		}
	}
}

func TestGetErrorPatterns_NonEmpty(t *testing.T) {
	got := GetErrorPatterns()
	if len(got) < 6 {
		t.Errorf("expected at least 6 PHP error patterns, got %d", len(got))
	}
	for _, p := range got {
		lp := strings.ToLower(p)
		if !strings.Contains(lp, "php") &&
			!strings.Contains(lp, "fatal error") &&
			!strings.Contains(lp, "parse error") &&
			!strings.Contains(lp, "warning") &&
			!strings.Contains(lp, "stack trace") &&
			!strings.Contains(lp, "deprecated") {
			t.Errorf("error pattern %q is not PHP-class", p)
		}
	}
}
