package checkpoint

import (
	"path/filepath"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
)

func TestCheckpoint_LoadMissingIsEmpty(t *testing.T) {
	cp, err := Load(filepath.Join(t.TempDir(), "none.json"))
	if err != nil {
		t.Fatalf("missing checkpoint must not error: %v", err)
	}
	if cp.Done("https://x/") || len(cp.Findings) != 0 {
		t.Error("missing checkpoint must be empty")
	}
}

func TestCheckpoint_RecordAndResume(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cp.json")

	cp, _ := Load(path)
	f := core.NewFinding("SQL Injection", core.SeverityHigh)
	f.URL = "https://t/a?id=1"
	if err := cp.Record(path, "https://t/a", core.Findings{f}); err != nil {
		t.Fatal(err)
	}
	// Re-recording the same target is a no-op (no duplicate finding).
	if err := cp.Record(path, "https://t/a", core.Findings{f}); err != nil {
		t.Fatal(err)
	}

	// A fresh load (resume) sees the completed target and carries its findings.
	resumed, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !resumed.Done("https://t/a") {
		t.Error("resume must know the target was scanned")
	}
	if resumed.Done("https://t/b") {
		t.Error("an unscanned target must not be marked done")
	}
	if len(resumed.Findings) != 1 {
		t.Errorf("resume carried %d findings, want 1 (no duplicate)", len(resumed.Findings))
	}
	if resumed.Findings[0].Type != "SQL Injection" {
		t.Errorf("carried finding = %q", resumed.Findings[0].Type)
	}
}
