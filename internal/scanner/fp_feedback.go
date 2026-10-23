package scanner

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/TyrusRC/assay/internal/core"
)

// FPFeedback tracks findings that were marked as false positives.
// Findings whose dedup key appears in the database get their confidence
// downgraded so repeated scans suppress known noise.
type FPFeedback struct {
	mu       sync.RWMutex
	database map[string]fpEntry
	path     string
}

type fpEntry struct {
	Key    string `json:"key"`
	Title  string `json:"title,omitempty"`
	URL    string `json:"url,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// LoadFPFeedback loads the FP database from path. Returns an empty
// database when the file does not exist.
func LoadFPFeedback(path string) *FPFeedback {
	fp := &FPFeedback{
		database: make(map[string]fpEntry),
		path:     path,
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fp
	}
	var entries []fpEntry
	if json.Unmarshal(data, &entries) == nil {
		for _, e := range entries {
			fp.database[e.Key] = e
		}
	}
	return fp
}

// MarkFP records a finding as a false positive.
func (fp *FPFeedback) MarkFP(finding *core.Finding, reason string) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	key := finding.DeduplicationKey()
	fp.database[key] = fpEntry{
		Key:    key,
		Title:  finding.Title,
		URL:    finding.URL,
		Reason: reason,
	}
}

// IsFP returns true when the finding matches a known false positive.
func (fp *FPFeedback) IsFP(finding *core.Finding) bool {
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	_, ok := fp.database[finding.DeduplicationKey()]
	return ok
}

// Save writes the FP database to disk.
func (fp *FPFeedback) Save() error {
	fp.mu.RLock()
	entries := make([]fpEntry, 0, len(fp.database))
	for _, e := range fp.database {
		entries = append(entries, e)
	}
	fp.mu.RUnlock()

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(fp.path, data, 0644)
}

// Count returns the number of FP entries.
func (fp *FPFeedback) Count() int {
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	return len(fp.database)
}

// ApplyToFindings downgrades confidence of findings matching the FP database.
func (fp *FPFeedback) ApplyToFindings(findings core.Findings) int {
	count := 0
	for _, f := range findings {
		if fp.IsFP(f) {
			f.Confidence = core.ConfidenceLow
			if f.Metadata == nil {
				f.Metadata = make(map[string]interface{})
			}
			f.Metadata["fp_suppressed"] = true
			count++
		}
	}
	return count
}
