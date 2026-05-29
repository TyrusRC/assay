package webauthn

import (
	"strings"
	"testing"
)

func TestGetPayloads_MinCount(t *testing.T) {
	got := GetPayloads()
	if len(got) < 15 {
		t.Errorf("expected at least 15 WebAuthn payloads, got %d", len(got))
	}
}

func TestGetPayloads_Shape(t *testing.T) {
	validClass := map[Class]bool{
		ClassOriginSpoof:       true,
		ClassRPIDMismatch:      true,
		ClassAttestationBypass: true,
		ClassCounterRegression: true,
		ClassCredentialIDReuse: true,
		ClassUserVerification:  true,
		ClassChallengeReuse:    true,
		ClassClientDataInject:  true,
	}
	validImpact := map[Impact]bool{
		ImpactAccountTakeover: true,
		ImpactAuthBypass:      true,
		ImpactInfoLeak:        true,
		ImpactRegistration:    true,
	}
	validPhase := map[Phase]bool{
		PhaseRegistration:   true,
		PhaseAuthentication: true,
		PhaseBoth:           true,
	}
	for _, p := range GetPayloads() {
		if p.Description == "" {
			t.Errorf("payload %q has empty Description", p.MutationHint)
		}
		if !validClass[p.Class] {
			t.Errorf("payload %q has invalid Class %q", p.MutationHint, p.Class)
		}
		if !validImpact[p.Impact] {
			t.Errorf("payload %q has invalid Impact %q", p.MutationHint, p.Impact)
		}
		if !validPhase[p.Phase] {
			t.Errorf("payload %q has invalid Phase %q", p.MutationHint, p.Phase)
		}
		if p.MutationHint == "" {
			t.Errorf("payload %s has empty MutationHint", p.Description)
		}
	}
}

func TestGetPayloads_CoverEveryClass(t *testing.T) {
	all := GetPayloads()
	classes := []Class{
		ClassOriginSpoof,
		ClassRPIDMismatch,
		ClassAttestationBypass,
		ClassCounterRegression,
		ClassCredentialIDReuse,
		ClassUserVerification,
		ClassChallengeReuse,
		ClassClientDataInject,
	}
	for _, c := range classes {
		found := false
		for _, p := range all {
			if p.Class == c {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no payload for class %q", c)
		}
	}
}

func TestGetByPhase_BothMatchesEverything(t *testing.T) {
	regPayloads := GetByPhase(PhaseRegistration)
	authPayloads := GetByPhase(PhaseAuthentication)
	// Every PhaseBoth payload should appear in both queries.
	for _, p := range GetPayloads() {
		if p.Phase != PhaseBoth {
			continue
		}
		inReg := false
		inAuth := false
		for _, q := range regPayloads {
			if q.Description == p.Description {
				inReg = true
			}
		}
		for _, q := range authPayloads {
			if q.Description == p.Description {
				inAuth = true
			}
		}
		if !inReg || !inAuth {
			t.Errorf("PhaseBoth payload missing from one of the per-phase queries: reg=%v auth=%v desc=%q", inReg, inAuth, p.Description)
		}
	}
}

func TestErrorPatterns_NonEmpty(t *testing.T) {
	got := ErrorPatterns()
	if len(got) < 8 {
		t.Errorf("expected at least 8 fingerprint patterns, got %d", len(got))
	}
	required := []string{"clientDataJSON", "authenticatorData", "rpId", "credentialId"}
	for _, r := range required {
		found := false
		for _, p := range got {
			if strings.Contains(p, r) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing required fingerprint marker: %q", r)
		}
	}
}

func TestCommonEndpoints_NonEmpty(t *testing.T) {
	got := CommonEndpoints()
	if len(got) < 10 {
		t.Errorf("expected at least 10 WebAuthn endpoint patterns, got %d", len(got))
	}
	required := []string{
		"/webauthn/register",
		"/webauthn/login",
		"/api/passkey/login",
		"/fido2/attestation/options",
	}
	for _, r := range required {
		found := false
		for _, p := range got {
			if p == r {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing required endpoint: %q", r)
		}
	}
}

func TestGetByClass(t *testing.T) {
	got := GetByClass(ClassOriginSpoof)
	if len(got) == 0 {
		t.Error("expected at least one origin-spoof payload")
	}
	for _, p := range got {
		if p.Class != ClassOriginSpoof {
			t.Errorf("GetByClass(origin_spoof) returned %q", p.Class)
		}
	}
}
