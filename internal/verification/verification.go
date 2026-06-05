// Package verification confirms candidate findings by safely re-exercising
// them. A finding that a verifier can reproduce is upgraded to
// ConfidenceConfirmed and marked Verified, with a reproducible proof attached;
// findings a verifier cannot reproduce are left untouched (never downgraded),
// so a verifier that simply fails to reach the bug does not hide it.
//
// All verifiers are read-only: they re-issue benign, side-effect-free requests
// and inject unique non-destructive markers. This mirrors the "proof-based"
// scanning model used to drive false positives toward zero.
package verification

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/TyrusRC/assay/internal/core"
	httpx "github.com/TyrusRC/assay/internal/http"
)

// Proof is the outcome of attempting to confirm a finding.
type Proof struct {
	// Method names the confirmation technique (e.g. "location-header").
	Method string
	// Detail is a short human-readable description of the proof.
	Detail string
	// Confirmed reports whether the finding was reproduced.
	Confirmed bool
}

// Verifier reproduces a single class of finding. Implementations must be
// read-only and must not mutate the target's state.
type Verifier interface {
	// Verify attempts to reproduce f using client. A nil proof (or one with
	// Confirmed=false) means the finding could not be confirmed.
	Verify(ctx context.Context, f *core.Finding, client *httpx.Client) (*Proof, error)
}

// Engine runs registered verifiers over findings, keyed by finding type.
type Engine struct {
	client    *httpx.Client
	verifiers map[string]Verifier
}

// Summary aggregates the outcome of a VerifyAll pass.
type Summary struct {
	// Attempted counts findings that had a matching verifier.
	Attempted int
	// Confirmed counts findings that were reproduced.
	Confirmed int
}

// NewEngine creates an Engine with the default verifiers registered.
func NewEngine(client *httpx.Client) *Engine {
	e := &Engine{
		client:    client,
		verifiers: make(map[string]Verifier),
	}
	e.Register("Open Redirect", openRedirectVerifier{})
	e.Register("Cross-Site Scripting (XSS)", reflectedXSSVerifier{})
	e.Register("Server-Side Template Injection (SSTI)", sstiVerifier{})
	e.Register("Local File Inclusion / Path Traversal", lfiVerifier{})
	e.Register("CRLF Injection", crlfVerifier{})
	e.Register("SQL Injection", sqliBooleanVerifier{})
	e.Register("SQL Injection (boolean-blind)", sqliBooleanVerifier{})
	return e
}

// Register associates a verifier with a finding type, replacing any existing
// verifier for that type.
func (e *Engine) Register(findingType string, v Verifier) {
	e.verifiers[findingType] = v
}

// Verify confirms a single finding. The boolean reports whether a verifier was
// registered for the finding's type. On a confirmed proof the finding is
// upgraded in place to ConfidenceConfirmed and marked Verified.
func (e *Engine) Verify(ctx context.Context, f *core.Finding) (*Proof, bool) {
	v, ok := e.verifiers[f.Type]
	if !ok {
		return nil, false
	}
	proof, err := v.Verify(ctx, f, e.client)
	if err != nil || proof == nil || !proof.Confirmed {
		return proof, true
	}
	applyProof(f, proof)
	return proof, true
}

// VerifyAll confirms every finding that has a registered verifier and returns a
// summary of the pass.
func (e *Engine) VerifyAll(ctx context.Context, findings core.Findings) Summary {
	var sum Summary
	for _, f := range findings {
		proof, attempted := e.Verify(ctx, f)
		if !attempted {
			continue
		}
		sum.Attempted++
		if proof != nil && proof.Confirmed {
			sum.Confirmed++
		}
	}
	return sum
}

// applyProof upgrades a finding once it has been reproduced.
func applyProof(f *core.Finding, proof *Proof) {
	f.Verified = true
	f.Confidence = core.ConfidenceConfirmed
	if f.Metadata == nil {
		f.Metadata = make(map[string]interface{})
	}
	f.Metadata["verification"] = proof.Method
	if proof.Detail != "" {
		if f.Evidence != "" {
			f.Evidence += "\n"
		}
		f.Evidence += "verified: " + proof.Detail
	}
}

// marker returns a short, unique, URL-safe token for use in verification
// payloads so reflections can be attributed unambiguously.
func marker() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "assayverify"
	}
	return "assay" + hex.EncodeToString(b)
}

// requestMethod returns the HTTP method recorded on a finding, defaulting to
// GET when none was captured.
func requestMethod(f *core.Finding) string {
	if f.Metadata != nil {
		if m, ok := f.Metadata["method"].(string); ok && m != "" {
			return strings.ToUpper(m)
		}
	}
	return "GET"
}
