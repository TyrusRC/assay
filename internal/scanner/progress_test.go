package scanner

import (
	"sync"
	"testing"
)

func TestNewProgress(t *testing.T) {
	p := NewProgress(100, false)

	if p == nil {
		t.Fatal("NewProgress() returned nil")
	}
	if p.totalParams != 100 {
		t.Errorf("totalParams = %d, want 100", p.totalParams)
	}
	if p.Phase() != "initializing" {
		t.Errorf("Phase() = %q, want %q", p.Phase(), "initializing")
	}
	if p.TestedParams() != 0 {
		t.Errorf("TestedParams() = %d, want 0", p.TestedParams())
	}
	if p.FindingsCount() != 0 {
		t.Errorf("FindingsCount() = %d, want 0", p.FindingsCount())
	}
}

func TestProgress_IncrementTested(t *testing.T) {
	p := NewProgress(10, false)

	p.IncrementTested()
	p.IncrementTested()
	p.IncrementTested()

	if got := p.TestedParams(); got != 3 {
		t.Errorf("TestedParams() = %d, want 3", got)
	}
}

func TestProgress_IncrementFindings(t *testing.T) {
	p := NewProgress(10, false)

	p.IncrementFindings(2)
	p.IncrementFindings(3)

	if got := p.FindingsCount(); got != 5 {
		t.Errorf("FindingsCount() = %d, want 5", got)
	}
}

func TestProgress_SetPhase(t *testing.T) {
	p := NewProgress(10, false)

	p.SetPhase("scanning")
	if got := p.Phase(); got != "scanning" {
		t.Errorf("Phase() = %q, want %q", got, "scanning")
	}

	p.SetPhase("reporting")
	if got := p.Phase(); got != "reporting" {
		t.Errorf("Phase() = %q, want %q", got, "reporting")
	}
}

func TestProgress_ConcurrentIncrementTested(t *testing.T) {
	const goroutines = 100
	const incrementsPerGoroutine = 50
	p := NewProgress(goroutines*incrementsPerGoroutine, false)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			for range incrementsPerGoroutine {
				p.IncrementTested()
			}
		}()
	}

	wg.Wait()

	expected := int64(goroutines * incrementsPerGoroutine)
	if got := p.TestedParams(); got != expected {
		t.Errorf("TestedParams() = %d, want %d", got, expected)
	}
}

func TestProgress_ConcurrentIncrementFindings(t *testing.T) {
	const goroutines = 100
	p := NewProgress(100, false)

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			p.IncrementFindings(1)
		}()
	}

	wg.Wait()

	if got := p.FindingsCount(); got != int64(goroutines) {
		t.Errorf("FindingsCount() = %d, want %d", got, goroutines)
	}
}

func TestProgress_ConcurrentSetPhase(t *testing.T) {
	p := NewProgress(10, false)
	phases := []string{"phase1", "phase2", "phase3", "phase4", "phase5"}

	var wg sync.WaitGroup
	wg.Add(len(phases))

	for _, phase := range phases {
		go func(ph string) {
			defer wg.Done()
			p.SetPhase(ph)
		}(phase)
	}

	wg.Wait()

	// Phase should be one of the set phases (no panic or race)
	got := p.Phase()
	found := false
	for _, ph := range phases {
		if got == ph {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Phase() = %q, expected one of %v", got, phases)
	}
}

func TestProgress_ConcurrentMixedOps(t *testing.T) {
	p := NewProgress(1000, false)

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		for range 100 {
			p.IncrementTested()
		}
	}()

	go func() {
		defer wg.Done()
		for range 50 {
			p.IncrementFindings(1)
		}
	}()

	go func() {
		defer wg.Done()
		for range 20 {
			p.SetPhase("testing")
		}
	}()

	wg.Wait()

	if got := p.TestedParams(); got != 100 {
		t.Errorf("TestedParams() = %d, want 100", got)
	}
	if got := p.FindingsCount(); got != 50 {
		t.Errorf("FindingsCount() = %d, want 50", got)
	}
}

func TestProgress_Finish(t *testing.T) {
	// Just verify Finish doesn't panic with enabled=false
	p := NewProgress(10, false)
	p.IncrementFindings(3)
	p.Finish()

	if got := p.FindingsCount(); got != 3 {
		t.Errorf("FindingsCount() = %d, want 3 after Finish()", got)
	}
}
