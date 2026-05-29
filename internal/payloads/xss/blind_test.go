package xss

import (
	"strings"
	"testing"
)

func TestGetBlindPayloads_MinCount(t *testing.T) {
	got := GetBlindPayloads()
	if len(got) < 10 {
		t.Errorf("expected at least 10 blind/OOB XSS payloads, got %d", len(got))
	}
}

func TestGetBlindPayloads_HaveOASTPlaceholder(t *testing.T) {
	got := GetBlindPayloads()
	if len(got) == 0 {
		t.Fatal("no blind payloads to assert against")
	}
	for _, p := range got {
		if !strings.Contains(p.Value, "{OAST_HOST}") {
			t.Errorf("blind XSS payload missing {OAST_HOST} placeholder: %q", p.Value)
		}
		if p.Type != TypeBlind {
			t.Errorf("blind XSS payload has Type=%q, want %q: %q", p.Type, TypeBlind, p.Value)
		}
	}
}

func TestGetBlindPayloads_CoverCommonExfilChannels(t *testing.T) {
	got := GetBlindPayloads()
	joined := ""
	for _, p := range got {
		joined += p.Value + "\n"
	}
	required := []string{
		"<script src=",                 // remote script include
		"<img src=",                    // image-based exfil
		"fetch(",                       // fetch() exfil
		"new Image",                    // Image() exfil
		"navigator.sendBeacon",         // Beacon exfil
		"document.cookie",              // cookie exfil reference
	}
	for _, r := range required {
		if !strings.Contains(joined, r) {
			t.Errorf("blind XSS bank missing required exfil channel: %q", r)
		}
	}
}

func TestBlindPayloadType_Constant(t *testing.T) {
	if TypeBlind == "" {
		t.Error("TypeBlind constant must be defined and non-empty")
	}
	if TypeBlind == TypeReflected || TypeBlind == TypeStored || TypeBlind == TypeDOM {
		t.Errorf("TypeBlind must be a distinct PayloadType, got %q", TypeBlind)
	}
}

func TestBlindPayloads_InAggregate(t *testing.T) {
	all := GetAllPayloads()
	blind := 0
	for _, p := range all {
		if p.Type == TypeBlind {
			blind++
		}
	}
	if blind == 0 {
		t.Error("GetAllPayloads must include blind XSS payloads")
	}
}
