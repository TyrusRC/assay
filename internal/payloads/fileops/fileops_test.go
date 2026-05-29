package fileops

import (
	"strings"
	"testing"
)

func TestGetPayloads_MinCount(t *testing.T) {
	got := GetPayloads()
	if len(got) < 18 {
		t.Errorf("expected at least 18 file-ops payloads, got %d", len(got))
	}
}

func TestGetPayloads_Shape(t *testing.T) {
	validOp := map[Operation]bool{
		OperationCreate: true,
		OperationDelete: true,
		OperationTamper: true,
	}
	for _, p := range GetPayloads() {
		if p.Value == "" {
			t.Errorf("payload has empty Value")
		}
		if !validOp[p.Operation] {
			t.Errorf("payload %q has invalid Operation %q", p.Value, p.Operation)
		}
	}
}

func TestGetByOperation_AllThreeBuckets(t *testing.T) {
	for _, op := range []Operation{OperationCreate, OperationDelete, OperationTamper} {
		got := GetByOperation(op)
		if len(got) == 0 {
			t.Errorf("no payloads for operation %q", op)
		}
	}
}

func TestGetPayloads_CoverTraversalPrimitives(t *testing.T) {
	joined := ""
	for _, p := range GetPayloads() {
		joined += p.Value + "\n"
	}
	required := []string{
		"../",            // POSIX traversal
		"..\\",           // Windows traversal
		"%2e%2e",         // URL-encoded
		"....//",         // double-dot bypass
		"%00",            // NULL-byte (PHP < 5.3)
	}
	for _, r := range required {
		if !strings.Contains(joined, r) {
			t.Errorf("file-ops bank missing required traversal primitive: %q", r)
		}
	}
}

func TestVerifyMarker_ConsistentFormat(t *testing.T) {
	m := VerifyMarker()
	if !strings.HasPrefix(m, "assay-fileops-") {
		t.Errorf("VerifyMarker must be prefixed for safe scrubbing, got %q", m)
	}
	if len(m) < 32 {
		t.Errorf("VerifyMarker too short to avoid collisions, got %q", m)
	}
}
