package scanner

import "sync"

// skipRules defines which detectors to skip when a given detector confirms a finding.
var skipRules = map[string][]string{
	"sqli": {"nosql", "xpath", "ldap"},
	"ssti": {"xss", "csti"},
	"cmdi": {"sqli", "xss", "ssrf", "lfi", "xxe", "nosql", "ssti",
		"redirect", "crlf", "ldap", "xpath", "headerinj", "csti", "rfi"},
}

// confirmedFindings tracks which vulnerability types have been confirmed
// per parameter, enabling intelligent skipping of redundant detectors.
type confirmedFindings struct {
	mu        sync.RWMutex
	confirmed map[string]map[string]bool
}

// newConfirmedFindings creates a new confirmedFindings tracker.
func newConfirmedFindings() *confirmedFindings {
	return &confirmedFindings{
		confirmed: make(map[string]map[string]bool),
	}
}

// confirm records that a detector found a confirmed vulnerability on a parameter.
func (cf *confirmedFindings) confirm(paramName, detectorName string) {
	cf.mu.Lock()
	defer cf.mu.Unlock()
	if cf.confirmed[paramName] == nil {
		cf.confirmed[paramName] = make(map[string]bool)
	}
	cf.confirmed[paramName][detectorName] = true
}

// shouldSkip returns true if running detectorName on paramName is redundant
// because a higher-priority vulnerability has already been confirmed.
func (cf *confirmedFindings) shouldSkip(paramName, detectorName string) bool {
	cf.mu.RLock()
	defer cf.mu.RUnlock()

	paramConfirmed := cf.confirmed[paramName]
	if paramConfirmed == nil {
		return false
	}

	for confirmedDetector := range paramConfirmed {
		skippable, ok := skipRules[confirmedDetector]
		if !ok {
			continue
		}
		for _, skip := range skippable {
			if skip == detectorName {
				return true
			}
		}
	}
	return false
}
