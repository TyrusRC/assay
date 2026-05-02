package scanner

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// Progress tracks scan progress for real-time output.
type Progress struct {
	totalParams   int64
	testedParams  int64
	findingsCount int64
	currentPhase  atomic.Value
	startTime     time.Time
	enabled       bool
}

// NewProgress creates a new progress tracker.
func NewProgress(totalParams int, enabled bool) *Progress {
	p := &Progress{
		totalParams: int64(totalParams),
		startTime:   time.Now(),
		enabled:     enabled,
	}
	p.currentPhase.Store("initializing")
	return p
}

// IncrementTested atomically increments the tested parameter count and prints progress.
func (p *Progress) IncrementTested() {
	tested := atomic.AddInt64(&p.testedParams, 1)
	if p.enabled {
		elapsed := time.Since(p.startTime).Round(time.Second)
		phase := p.currentPhase.Load().(string)
		fmt.Fprintf(os.Stderr, "\r[%s] %s | %d/%d params | %d findings found",
			elapsed, phase, tested, p.totalParams, atomic.LoadInt64(&p.findingsCount))
	}
}

// IncrementFindings atomically adds the given count to the findings counter.
func (p *Progress) IncrementFindings(count int) {
	atomic.AddInt64(&p.findingsCount, int64(count))
}

// SetPhase updates the current scan phase label.
func (p *Progress) SetPhase(phase string) {
	p.currentPhase.Store(phase)
	if p.enabled {
		fmt.Fprintf(os.Stderr, "\n[*] %s\n", phase)
	}
}

// Finish prints the final scan completion summary.
func (p *Progress) Finish() {
	if p.enabled {
		elapsed := time.Since(p.startTime).Round(time.Second)
		fmt.Fprintf(os.Stderr, "\n[+] Scan complete in %s | %d findings\n",
			elapsed, atomic.LoadInt64(&p.findingsCount))
	}
}

// TestedParams returns the current tested parameter count.
func (p *Progress) TestedParams() int64 {
	return atomic.LoadInt64(&p.testedParams)
}

// FindingsCount returns the current findings count.
func (p *Progress) FindingsCount() int64 {
	return atomic.LoadInt64(&p.findingsCount)
}

// Phase returns the current phase.
func (p *Progress) Phase() string {
	return p.currentPhase.Load().(string)
}
