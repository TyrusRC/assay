// Package checkpoint persists scan progress so a long or daily scan can resume
// after an interruption instead of starting over. Granularity is the scan
// target: a target is recorded complete once all its detectors have run, along
// with the findings produced so far.
package checkpoint

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TyrusRC/assay/internal/core"
)

// Checkpoint is the resumable state of a scan.
type Checkpoint struct {
	Completed []string      `json:"completed"` // target URLs fully scanned
	Findings  core.Findings `json:"findings"`
	UpdatedAt time.Time     `json:"updated_at"`

	done map[string]bool
}

// Load reads a checkpoint from path. A missing file returns an empty, ready
// checkpoint (not an error) so --resume on a first run just starts fresh.
func Load(path string) (*Checkpoint, error) {
	cp := &Checkpoint{done: make(map[string]bool)}
	if path == "" {
		return cp, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cp, nil
		}
		return nil, fmt.Errorf("checkpoint: read %s: %w", path, err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, cp); err != nil {
			return nil, fmt.Errorf("checkpoint: parse %s: %w", path, err)
		}
	}
	cp.done = make(map[string]bool, len(cp.Completed))
	for _, u := range cp.Completed {
		cp.done[u] = true
	}
	return cp, nil
}

// Done reports whether targetURL was already scanned in a prior run.
func (c *Checkpoint) Done(targetURL string) bool {
	return c.done[targetURL]
}

// Record marks targetURL complete, appends its findings, and persists to path
// (atomic temp+rename). A re-recorded target is ignored.
func (c *Checkpoint) Record(path, targetURL string, findings core.Findings) error {
	if c.done == nil {
		c.done = make(map[string]bool)
	}
	if !c.done[targetURL] {
		c.done[targetURL] = true
		c.Completed = append(c.Completed, targetURL)
		c.Findings = append(c.Findings, findings...)
	}
	c.UpdatedAt = time.Now()
	return c.save(path)
}

func (c *Checkpoint) save(path string) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
