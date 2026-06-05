package api

import (
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/scanner"
)

func TestStore_CreateGetList(t *testing.T) {
	s := NewStore()
	a := s.Create(ScanRequest{Target: "https://a"})
	b := s.Create(ScanRequest{Target: "https://b"})

	if a.ID == b.ID {
		t.Fatal("ids must be unique")
	}
	if a.Status != StatusQueued {
		t.Errorf("new job status = %q, want queued", a.Status)
	}

	got, ok := s.Get(a.ID)
	if !ok || got.Target != "https://a" {
		t.Errorf("Get = %+v, %v", got, ok)
	}
	if _, ok := s.Get("missing"); ok {
		t.Error("Get(missing) should be false")
	}

	list := s.List()
	if len(list) != 2 || list[0].ID != a.ID || list[1].ID != b.ID {
		t.Errorf("List order wrong: %+v", list)
	}
}

func TestStore_Transitions(t *testing.T) {
	s := NewStore()
	job := s.Create(ScanRequest{Target: "https://x"})

	s.setRunning(job.ID)
	if got, _ := s.Get(job.ID); got.Status != StatusRunning {
		t.Errorf("status = %q, want running", got.Status)
	}

	f := core.NewFinding("XSS", core.SeverityHigh)
	f.URL = "https://x"
	s.setCompleted(job.ID, &scanner.ScanResult{Findings: core.Findings{f}})
	got, _ := s.Get(job.ID)
	if got.Status != StatusCompleted {
		t.Errorf("status = %q, want completed", got.Status)
	}
	if got.Summary == nil || got.Summary.High != 1 {
		t.Errorf("summary = %+v, want 1 high", got.Summary)
	}
	if got.Result() == nil {
		t.Error("Result() should be set after completion")
	}
}

func TestStore_SetFailed(t *testing.T) {
	s := NewStore()
	job := s.Create(ScanRequest{Target: "https://x"})
	s.setFailed(job.ID, "kaboom")
	got, _ := s.Get(job.ID)
	if got.Status != StatusFailed || got.Error != "kaboom" {
		t.Errorf("job = %+v, want failed/kaboom", got)
	}
}

// TestStore_CopyIsolation ensures handed-out jobs don't alias internal state.
func TestStore_CopyIsolation(t *testing.T) {
	s := NewStore()
	job := s.Create(ScanRequest{Target: "https://x"})
	job.Status = StatusFailed // mutate the returned copy
	if got, _ := s.Get(job.ID); got.Status != StatusQueued {
		t.Errorf("internal status mutated to %q; copies must be isolated", got.Status)
	}
}
