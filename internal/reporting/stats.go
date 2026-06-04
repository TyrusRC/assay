package reporting

import (
	"regexp"

	"github.com/TyrusRC/assay/internal/core"
)

// reportStats holds aggregate counts derived from a finding set, used by the
// HTML/Markdown renderers. Computed in the reporting layer so scanner stays
// untouched.
type reportStats struct {
	Total         int
	BySeverity    map[core.Severity]int
	ByType        map[string]int
	OWASPCoverage map[string]int // normalized Axx prefix -> count
	HighestCVSS   float64
}

var owaspPrefix = regexp.MustCompile(`^(A\d{2})`)

// computeStats aggregates a finding set.
func computeStats(findings core.Findings) reportStats {
	s := reportStats{
		BySeverity:    make(map[core.Severity]int),
		ByType:        make(map[string]int),
		OWASPCoverage: make(map[string]int),
	}
	s.Total = len(findings)
	for _, f := range findings {
		if f == nil {
			continue
		}
		s.BySeverity[f.Severity]++
		s.ByType[f.Type]++
		if f.CVSS > s.HighestCVSS {
			s.HighestCVSS = f.CVSS
		}
		for _, code := range f.Top10 {
			if m := owaspPrefix.FindStringSubmatch(code); m != nil {
				s.OWASPCoverage[m[1]]++
			}
		}
	}
	return s
}
