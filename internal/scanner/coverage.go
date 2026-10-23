package scanner

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// CoverageRecord logs one (param, detector) test outcome.
type CoverageRecord struct {
	URL       string        `json:"url"`
	Parameter string        `json:"parameter"`
	Location  string        `json:"location"` // body, query, header, cookie, path
	Detector  string        `json:"detector"` // sqli, xss, cmdi, etc.
	Status    string        `json:"status"`   // tested, skipped, error, timeout
	Findings  int           `json:"findings"`
	Duration  time.Duration `json:"duration_ns"`
}

// CoverageSummary aggregates coverage statistics.
type CoverageSummary struct {
	TotalParams    int            `json:"total_params"`
	TestedParams   int            `json:"tested_params"`
	SkippedParams  int            `json:"skipped_params"`
	ErrorParams    int            `json:"error_params"`
	TotalRecords   int            `json:"total_records"`
	ByDetector     map[string]int `json:"by_detector"`
	ByLocation     map[string]int `json:"by_location"`
	ByStatus       map[string]int `json:"by_status"`
	FindingsCount  int            `json:"findings_count"`
	DetectorsUsed  []string       `json:"detectors_used"`
	UniqueParams   int            `json:"unique_params"`
}

// CoverageTracker records which (param, detector) pairs have been tested.
type CoverageTracker struct {
	mu      sync.RWMutex
	records []CoverageRecord
}

// NewCoverageTracker creates a new coverage tracker.
func NewCoverageTracker() *CoverageTracker {
	return &CoverageTracker{}
}

// Record adds a coverage record. Thread-safe.
func (ct *CoverageTracker) Record(r CoverageRecord) {
	ct.mu.Lock()
	ct.records = append(ct.records, r)
	ct.mu.Unlock()
}

// Records returns a copy of all records.
func (ct *CoverageTracker) Records() []CoverageRecord {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	out := make([]CoverageRecord, len(ct.records))
	copy(out, ct.records)
	return out
}

// Summary computes aggregate statistics from all records.
func (ct *CoverageTracker) Summary() CoverageSummary {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	s := CoverageSummary{
		TotalRecords: len(ct.records),
		ByDetector:   make(map[string]int),
		ByLocation:   make(map[string]int),
		ByStatus:     make(map[string]int),
	}

	paramSet := map[string]bool{}
	testedParams := map[string]bool{}
	skippedParams := map[string]bool{}
	errorParams := map[string]bool{}
	detectorSet := map[string]bool{}

	for _, r := range ct.records {
		key := r.URL + "|" + r.Parameter + "|" + r.Location
		paramSet[key] = true
		s.ByStatus[r.Status]++
		s.FindingsCount += r.Findings

		switch r.Status {
		case "tested":
			testedParams[key] = true
			s.ByDetector[r.Detector]++
			s.ByLocation[r.Location]++
			detectorSet[r.Detector] = true
		case "skipped":
			if !testedParams[key] {
				skippedParams[key] = true
			}
		case "error", "timeout":
			errorParams[key] = true
		}
	}

	s.UniqueParams = len(paramSet)
	s.TotalParams = len(paramSet)
	s.TestedParams = len(testedParams)
	s.SkippedParams = len(skippedParams)
	s.ErrorParams = len(errorParams)
	for d := range detectorSet {
		s.DetectorsUsed = append(s.DetectorsUsed, d)
	}

	return s
}

// WriteJSON writes the full coverage data to a JSON file.
func (ct *CoverageTracker) WriteJSON(path string) error {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	data := struct {
		Summary CoverageSummary  `json:"summary"`
		Records []CoverageRecord `json:"records"`
	}{
		Summary: ct.Summary(),
		Records: ct.records,
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(data)
}
