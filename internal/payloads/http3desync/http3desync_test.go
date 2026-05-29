package http3desync

import (
	"strings"
	"testing"
)

func TestGetPayloads_MinCount(t *testing.T) {
	got := GetPayloads()
	if len(got) < 10 {
		t.Errorf("expected at least 10 HTTP/3 desync payloads, got %d", len(got))
	}
}

func TestGetPayloads_Shape(t *testing.T) {
	validTechnique := map[Technique]bool{
		TechStreamSplit:         true,
		TechQPACKDesync:         true,
		TechAltSvcDowngrade:     true,
		TechConnectUDP:          true,
		TechZeroRTTReplay:       true,
		TechHeaderListSizeFlood: true,
	}
	validImpact := map[Impact]bool{
		ImpactSmuggle:     true,
		ImpactCachePoison: true,
		ImpactDoS:         true,
		ImpactInfoLeak:    true,
	}
	for _, p := range GetPayloads() {
		if p.Name == "" {
			t.Errorf("payload has empty Name")
		}
		if !validTechnique[p.Technique] {
			t.Errorf("payload %q has invalid Technique %q", p.Name, p.Technique)
		}
		if !validImpact[p.Impact] {
			t.Errorf("payload %q has invalid Impact %q", p.Name, p.Impact)
		}
		if p.FrameSeq == "" {
			t.Errorf("payload %q has empty FrameSeq", p.Name)
		}
		if p.FrontendVersion == "" {
			t.Errorf("payload %q has empty FrontendVersion", p.Name)
		}
	}
}

func TestGetPayloads_CoverEveryTechnique(t *testing.T) {
	all := GetPayloads()
	techs := []Technique{
		TechStreamSplit,
		TechQPACKDesync,
		TechAltSvcDowngrade,
		TechConnectUDP,
		TechZeroRTTReplay,
		TechHeaderListSizeFlood,
	}
	for _, tt := range techs {
		found := false
		for _, p := range all {
			if p.Technique == tt {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no payload for technique %q", tt)
		}
	}
}

func TestGetByTechnique(t *testing.T) {
	got := GetByTechnique(TechQPACKDesync)
	if len(got) == 0 {
		t.Error("expected at least one QPACK desync payload")
	}
	for _, p := range got {
		if p.Technique != TechQPACKDesync {
			t.Errorf("GetByTechnique returned %q", p.Technique)
		}
	}
}

func TestDiscoveryHeaders_NonEmpty(t *testing.T) {
	got := DiscoveryHeaders()
	if len(got) == 0 {
		t.Error("expected at least one discovery header")
	}
	// Must include Alt-Svc at minimum.
	found := false
	for _, h := range got {
		if strings.EqualFold(h, "Alt-Svc") {
			found = true
			break
		}
	}
	if !found {
		t.Error("DiscoveryHeaders must include Alt-Svc")
	}
}

func TestFrameMarkers_NonEmpty(t *testing.T) {
	got := FrameMarkers()
	if len(got) < 8 {
		t.Errorf("expected at least 8 H3/QPACK error markers, got %d", len(got))
	}
	required := []string{"H3_FRAME_ERROR", "QPACK_DECOMPRESSION_FAILED", "H3_REQUEST_INCOMPLETE"}
	for _, r := range required {
		found := false
		for _, m := range got {
			if m == r {
				found = true
			}
		}
		if !found {
			t.Errorf("missing required marker: %q", r)
		}
	}
}
