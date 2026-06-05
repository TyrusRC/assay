package reporting

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/TyrusRC/assay/internal/core"
)

// Delta is the result of comparing a baseline scan against the current scan.
type Delta struct {
	// New findings are present now but absent from the baseline.
	New core.Findings
	// Existing findings are present in both scans.
	Existing core.Findings
	// Fixed findings were in the baseline but are gone now.
	Fixed core.Findings
}

// DiffFindings compares baseline and current findings by deduplication key and
// classifies each as new, existing, or fixed. Ordering follows the current
// slice for New/Existing and the baseline slice for Fixed.
func DiffFindings(baseline, current core.Findings) Delta {
	baseKeys := make(map[string]bool, len(baseline))
	for _, f := range baseline {
		if f != nil {
			baseKeys[f.DeduplicationKey()] = true
		}
	}
	currKeys := make(map[string]bool, len(current))
	for _, f := range current {
		if f != nil {
			currKeys[f.DeduplicationKey()] = true
		}
	}

	var d Delta
	for _, f := range current {
		if f == nil {
			continue
		}
		if baseKeys[f.DeduplicationKey()] {
			d.Existing = append(d.Existing, f)
		} else {
			d.New = append(d.New, f)
		}
	}
	for _, f := range baseline {
		if f == nil {
			continue
		}
		if !currKeys[f.DeduplicationKey()] {
			d.Fixed = append(d.Fixed, f)
		}
	}
	return d
}

// LoadBaselineFindings reads a prior assay JSON report and returns its
// findings, for use as a diff baseline.
func LoadBaselineFindings(path string) (core.Findings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline %s: %w", path, err)
	}
	var doc struct {
		ScanResult struct {
			Findings core.Findings `json:"findings"`
		} `json:"scan_result"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	return doc.ScanResult.Findings, nil
}
