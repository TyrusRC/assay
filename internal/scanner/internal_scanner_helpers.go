// internal_scanner_helpers.go — helper functions used by Scan():
// parameter prioritization and partial-findings flush.
package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/TyrusRC/assay/internal/core"
)

// paramPriority assigns a numeric priority (lower = tested first) based on
// the parameter's location and classification.
//
//	0: body params with a vulnerable classification (id, file, url, etc.)
//	1: other body params
//	2: path segments
//	3: query params with a vulnerable classification
//	4: cookies
//	5: query params > 2 chars
//	6: spec-discovered headers (SourceURL set)
//	7: built-in header probes
//	8: single-char query params and noise
func paramPriority(p core.Parameter) int {
	switch p.Location {
	case "body":
		if p.IsPotentiallyVulnerable() {
			return 0
		}
		return 1
	case "path":
		return 2
	case "query":
		if p.IsPotentiallyVulnerable() {
			return 3
		}
		if len(p.Name) > 2 {
			return 5
		}
		return 8
	case "cookie":
		return 4
	case "header":
		if p.SourceURL != "" {
			return 6
		}
		return 7
	default:
		if p.SourceURL != "" {
			return 3
		}
		return 8
	}
}

// flushPartialFindings writes the current findings snapshot to
// <dir>/assay-partial.json. Called after each scan phase so findings
// from earlier phases survive if a later phase hangs or the process
// is killed. The partial file is removed on normal scan completion.
func flushPartialFindings(mu *sync.Mutex, findings *core.Findings, dir string) {
	if dir == "" {
		return
	}
	mu.Lock()
	n := len(*findings)
	if n == 0 {
		mu.Unlock()
		return
	}
	snapshot := make(core.Findings, n)
	copy(snapshot, *findings)
	mu.Unlock()

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, "assay-partial.json")
	if err := os.WriteFile(path, data, 0o644); err == nil {
		fmt.Fprintf(os.Stderr, "[*] Flushed %d partial findings to %s\n", n, path)
	}
}
