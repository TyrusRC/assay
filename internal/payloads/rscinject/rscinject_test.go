package rscinject

import (
	"strings"
	"testing"
)

func TestGetPayloads_MinCount(t *testing.T) {
	got := GetPayloads()
	if len(got) < 8 {
		t.Errorf("expected at least 8 RSC/Server-Action payloads, got %d", len(got))
	}
}

func TestGetPayloads_Shape(t *testing.T) {
	validVector := map[Vector]bool{
		VectorActionIDConfusion: true,
		VectorPayloadShape:      true,
		VectorHeaderInjection:   true,
		VectorCacheKey:          true,
		VectorComponentLeak:     true,
		VectorActionReplay:      true,
	}
	validImpact := map[Impact]bool{
		ImpactRCE:                 true,
		ImpactInfoLeak:            true,
		ImpactAuthBypass:          true,
		ImpactStateCorruption:     true,
		ImpactCachePoison:         true,
		ImpactPrivilegeEscalation: true,
		ImpactComponentLeak:       true,
	}
	for _, p := range GetPayloads() {
		if p.Name == "" {
			t.Errorf("payload has empty Name")
		}
		if !validVector[p.Vector] {
			t.Errorf("payload %q has invalid Vector %q", p.Name, p.Vector)
		}
		if !validImpact[p.Impact] {
			t.Errorf("payload %q has invalid Impact %q", p.Name, p.Impact)
		}
		if p.Method == "" {
			t.Errorf("payload %q has empty Method", p.Name)
		}
		if len(p.Headers) == 0 {
			t.Errorf("payload %q has no Headers", p.Name)
		}
	}
}

func TestGetPayloads_CoverEveryVector(t *testing.T) {
	all := GetPayloads()
	vectors := []Vector{
		VectorActionIDConfusion,
		VectorPayloadShape,
		VectorHeaderInjection,
		VectorCacheKey,
		VectorComponentLeak,
		VectorActionReplay,
	}
	for _, v := range vectors {
		found := false
		for _, p := range all {
			if p.Vector == v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no payload for vector %q", v)
		}
	}
}

func TestGetByVector(t *testing.T) {
	got := GetByVector(VectorActionIDConfusion)
	if len(got) == 0 {
		t.Error("expected at least one action-ID confusion payload")
	}
	for _, p := range got {
		if p.Vector != VectorActionIDConfusion {
			t.Errorf("GetByVector returned %q", p.Vector)
		}
	}
}

func TestFingerprints_NonEmpty(t *testing.T) {
	got := Fingerprints()
	if len(got) < 6 {
		t.Errorf("expected at least 6 RSC fingerprints, got %d", len(got))
	}
	required := []string{"__next_f.push", "Next-Action", "_next/static/chunks/app/"}
	for _, r := range required {
		found := false
		for _, p := range got {
			if strings.Contains(p, r) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing required fingerprint: %q", r)
		}
	}
}

func TestCommonHeaders_NonEmpty(t *testing.T) {
	got := CommonHeaders()
	if len(got) < 5 {
		t.Errorf("expected at least 5 RSC negotiation headers, got %d", len(got))
	}
	required := []string{"Next-Action", "Next-Router-State-Tree", "rsc"}
	for _, r := range required {
		found := false
		for _, h := range got {
			if h == r {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing required header: %q", r)
		}
	}
}

func TestPayloadsAcceptPlaceholders(t *testing.T) {
	// At least one payload must reference the runner-substituted
	// placeholders so the test exercises that contract.
	all := GetPayloads()
	gotActionID := false
	for _, p := range all {
		if v, ok := p.Headers["Next-Action"]; ok && v == "{{ACTION_ID}}" {
			gotActionID = true
		}
	}
	if !gotActionID {
		t.Error("expected at least one payload using the {{ACTION_ID}} placeholder")
	}
}
