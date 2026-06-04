package scoring

import "github.com/TyrusRC/assay/internal/core"

// Enrich fills the CVSS score and vector for findings that lack one. Findings
// that already carry a non-zero CVSS (e.g. NVD via jsdep, or nuclei) are left
// untouched - authoritative external scores win. Mutates findings in place.
func Enrich(findings core.Findings) {
	for _, f := range findings {
		if f == nil || f.CVSS > 0 {
			continue
		}
		vector := DefaultVector(f.CWE, f.Severity)
		if vector == "" {
			continue
		}
		m, err := ParseVector(vector)
		if err != nil {
			continue
		}
		f.CVSSVector = vector
		f.CVSS = m.BaseScore()
	}
}
