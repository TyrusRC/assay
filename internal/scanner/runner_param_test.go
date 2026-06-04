package scanner

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// TestRunParameterTests_DrivesProgress verifies that runParameterTests reports
// one tested parameter to the progress tracker per parameter, even when no
// detectors are enabled (so no HTTP requests are made).
func TestRunParameterTests_DrivesProgress(t *testing.T) {
	cfg := &InternalScanConfig{
		MaxPayloadsPerParam: 1,
		RequestTimeout:      5 * time.Second,
	}
	s, err := NewInternalScanner(cfg)
	if err != nil {
		t.Fatalf("NewInternalScanner() error = %v", err)
	}

	prog := NewProgress(3, false)
	params := []core.Parameter{
		{Name: "a", Location: core.ParamLocationQuery},
		{Name: "b", Location: core.ParamLocationQuery},
		{Name: "c", Location: core.ParamLocationQuery},
	}

	// No detectors are enabled, so runParamDetectors emits nothing; a buffered
	// channel is sufficient and no drain goroutine is required.
	ch := make(chan *core.Finding, len(params))

	var wg sync.WaitGroup
	s.runParameterTests(context.Background(), &wg, ch, params, "http://example.invalid", "GET", s.client, prog)
	wg.Wait()
	close(ch)

	if got := prog.TestedParams(); got != int64(len(params)) {
		t.Errorf("TestedParams() = %d, want %d", got, len(params))
	}
}
