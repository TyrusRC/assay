package scoring

import "github.com/TyrusRC/assay/internal/core"

// cweVectors maps the high-impact CWEs the detectors emit to a representative
// CVSS v3.1 base vector. Unmapped CWEs fall through to the severity table.
// These are default/representative scores, not context-specific assessments.
var cweVectors = map[string]string{
	"CWE-89":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // SQLi
	"CWE-78":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // OS command injection
	"CWE-94":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // code injection / SSTI
	"CWE-502":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // deserialization
	"CWE-918":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // SSRF
	"CWE-611":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // XXE
	"CWE-22":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // path traversal / LFI
	"CWE-98":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // RFI
	"CWE-79":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", // XSS
	"CWE-352":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", // CSRF
	"CWE-601":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", // open redirect
	"CWE-639":  "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", // IDOR / BOLA
	"CWE-862":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // missing authorization
	"CWE-287":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", // improper authentication
	"CWE-90":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", // LDAP injection
	"CWE-91":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", // XML injection
	"CWE-943":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", // NoSQL injection
	"CWE-93":   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", // CRLF
	"CWE-444":  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:N", // request smuggling
	"CWE-200":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", // info exposure
	"CWE-319":  "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", // cleartext transmission
	"CWE-400":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", // resource exhaustion / DoS
	"CWE-1321": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", // prototype pollution
}

// severityVectors maps a declared severity to a representative vector used when
// no CWE mapping is available. Info maps to an empty vector (score 0).
var severityVectors = map[core.Severity]string{
	core.SeverityCritical: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // 9.8
	core.SeverityHigh:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", // 7.5
	core.SeverityMedium:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N", // 5.4
	core.SeverityLow:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", // 3.1
	core.SeverityInfo:     "",
}

// DefaultVector returns a representative CVSS v3.1 vector for a finding, keyed
// first by any mapped CWE, then by the declared severity. Returns "" when no
// score should be assigned (e.g. Info with no CWE mapping).
func DefaultVector(cwes []string, sev core.Severity) string {
	for _, cwe := range cwes {
		if v, ok := cweVectors[cwe]; ok {
			return v
		}
	}
	return severityVectors[sev]
}
