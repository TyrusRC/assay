// Package longpwd detects authentication endpoints vulnerable to
// long-password denial-of-service. Modern password hashes (bcrypt,
// Argon2, scrypt) are intentionally slow per byte; an attacker who can
// submit a 100k+ character password and force the server to hash it
// burns one worker thread for seconds.
//
// Mirrors AWVS Long_Password_Denial_of_Service.script. The detector
// measures the response-time delta between a normal-length password and
// the largest probe — a large delta indicates the server forwards the
// entire string into the password-hash function instead of length-capping
// at the boundary (the django-style mitigation).
package longpwd

import (
	"strings"
	"time"
)

// Result reports the evaluation outcome.
type Result struct {
	Vulnerable bool
	Delta      time.Duration
	Notes      string
}

// GetPasswords returns the ladder of probe passwords. Lengths are
// chosen so the detector can find the inflection point even when
// the noise floor is high.
func GetPasswords() []string {
	return []string{
		strings.Repeat("A", 10),
		strings.Repeat("A", 100),
		strings.Repeat("A", 1000),
		strings.Repeat("A", 10000),
		strings.Repeat("A", 100000),
	}
}

// VulnerabilityThreshold is the minimum response-time delta (between a
// short-password baseline and the longest probe) that flags the endpoint
// as vulnerable. Below this, the delta is treated as network noise.
func VulnerabilityThreshold() time.Duration {
	return 2 * time.Second
}

// Evaluate compares two timings and reports a verdict. Negative deltas
// (long password faster) and tiny deltas (network noise) are not vuln.
func Evaluate(baseline, longProbe time.Duration) Result {
	delta := longProbe - baseline
	if delta <= 0 {
		return Result{Vulnerable: false, Delta: delta, Notes: "long-password response faster than baseline (server length-caps before hashing)"}
	}
	if delta < VulnerabilityThreshold() {
		return Result{Vulnerable: false, Delta: delta, Notes: "delta within network-noise floor"}
	}
	return Result{
		Vulnerable: true,
		Delta:      delta,
		Notes:      "server hashes full input — long password forces CPU burn per request, enabling cheap DoS",
	}
}
