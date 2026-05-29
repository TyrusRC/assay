package longpwd

import (
	"strings"
	"testing"
	"time"
)

func TestGetPasswords_LengthLadder(t *testing.T) {
	got := GetPasswords()
	if len(got) < 4 {
		t.Errorf("expected at least 4 password lengths, got %d", len(got))
	}
	// Lengths should escalate (10 → 100 → 10k → 100k+) so the detector
	// can find the response-time inflection point.
	prev := 0
	for _, p := range got {
		if len(p) <= prev {
			t.Errorf("password lengths must strictly increase: %d → %d", prev, len(p))
		}
		prev = len(p)
	}
}

func TestGetPasswords_LongestExceedsBcryptTruncation(t *testing.T) {
	got := GetPasswords()
	if len(got) == 0 {
		t.Fatal("no passwords")
	}
	longest := got[len(got)-1]
	if len(longest) < 100000 {
		t.Errorf("longest password (%d chars) too short to trigger Argon2 memory blowup", len(longest))
	}
}

func TestVulnerabilityThreshold_Sensible(t *testing.T) {
	if VulnerabilityThreshold() <= 0 {
		t.Errorf("VulnerabilityThreshold must be > 0")
	}
	if VulnerabilityThreshold() < 500*time.Millisecond {
		t.Errorf("VulnerabilityThreshold should be at least 500ms (network noise floor), got %v", VulnerabilityThreshold())
	}
}

func TestEvaluate_FlagsLargeDelta(t *testing.T) {
	res := Evaluate(50*time.Millisecond, 6*time.Second)
	if !res.Vulnerable {
		t.Errorf("expected Vulnerable=true when long pw takes >5s extra, got %+v", res)
	}
	if res.Delta <= 0 {
		t.Errorf("expected positive Delta, got %v", res.Delta)
	}
}

func TestEvaluate_NotVulnerableOnNoiseFloor(t *testing.T) {
	res := Evaluate(50*time.Millisecond, 60*time.Millisecond)
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false when delta is within noise (~10ms), got %+v", res)
	}
}

func TestEvaluate_NegativeDeltaSafe(t *testing.T) {
	// Long password actually returned faster (e.g. server rejected
	// at length check before hashing). Not vulnerable.
	res := Evaluate(2*time.Second, 50*time.Millisecond)
	if res.Vulnerable {
		t.Errorf("expected Vulnerable=false when long pw is FASTER, got %+v", res)
	}
}

func TestPasswordContent_NoNonASCII(t *testing.T) {
	// Long passwords should be plain ASCII so they don't get rejected
	// by the application's character-set filter and confuse the timing
	// signal.
	for _, p := range GetPasswords() {
		for _, r := range p {
			if r > 127 {
				t.Errorf("password contains non-ASCII rune %U (would cause filter-rejection false-negative)", r)
				break
			}
		}
	}
}

func TestPasswordContent_NoNullByte(t *testing.T) {
	for _, p := range GetPasswords() {
		if strings.ContainsRune(p, 0) {
			t.Errorf("password contains NULL byte (some servers truncate at \\x00)")
		}
	}
}
