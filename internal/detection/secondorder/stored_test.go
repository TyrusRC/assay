package secondorder

import (
	"strings"
	"testing"
)

func TestStoredStrategies_InDefaults(t *testing.T) {
	strategies := DefaultStrategies()
	names := make(map[string]bool, len(strategies))
	for _, s := range strategies {
		names[s.Name] = true
	}
	required := []string{
		StrategyStoredLFI,
		StrategyStoredCmdExec,
		StrategyStoredCodeExec,
	}
	for _, r := range required {
		if !names[r] {
			t.Errorf("DefaultStrategies missing %q", r)
		}
	}
}

func TestStoredLFI_PayloadShape(t *testing.T) {
	got := storedLFIPayloads()
	if len(got) < 4 {
		t.Errorf("expected at least 4 stored LFI payloads, got %d", len(got))
	}
	hasTraversal := false
	for _, p := range got {
		if strings.Contains(p, "../") || strings.Contains(p, "..\\") {
			hasTraversal = true
		}
	}
	if !hasTraversal {
		t.Errorf("stored LFI bank must include directory-traversal sequences")
	}
}

func TestStoredCmdExec_PayloadShape(t *testing.T) {
	got := storedCmdExecPayloads()
	if len(got) < 4 {
		t.Errorf("expected at least 4 stored cmd-exec payloads, got %d", len(got))
	}
	// At least one payload must contain a shell metacharacter.
	hasMeta := false
	for _, p := range got {
		if strings.ContainsAny(p, ";|&`$") {
			hasMeta = true
			break
		}
	}
	if !hasMeta {
		t.Errorf("stored cmd-exec bank must include shell metacharacters")
	}
}

func TestStoredCodeExec_PHPGate(t *testing.T) {
	got := storedCodeExecPayloads()
	if len(got) < 3 {
		t.Errorf("expected at least 3 stored PHP-code-exec payloads, got %d", len(got))
	}
	joined := ""
	for _, p := range got {
		joined += p + "\n"
	}
	required := []string{"<?php", "system(", "phpinfo("}
	for _, r := range required {
		if !strings.Contains(joined, r) {
			t.Errorf("stored code-exec bank missing %q", r)
		}
	}
}

func TestGetPayloads_StoredStrategies(t *testing.T) {
	for _, name := range []string{StrategyStoredLFI, StrategyStoredCmdExec, StrategyStoredCodeExec} {
		s := Strategy{Name: name}
		got := GetPayloads(s, "")
		if len(got) == 0 {
			t.Errorf("GetPayloads(%s) returned empty", name)
		}
	}
}

func TestDefaultStoredLFIStrategy_PopulatesURLs(t *testing.T) {
	s := DefaultStoredLFIStrategy("http://x/inject", "http://x/verify")
	if s.InjectURL != "http://x/inject" || s.VerifyURL != "http://x/verify" {
		t.Errorf("DefaultStoredLFIStrategy did not set inject/verify URLs: %+v", s)
	}
	if len(s.Payloads) == 0 {
		t.Errorf("DefaultStoredLFIStrategy returned no payloads")
	}
}
