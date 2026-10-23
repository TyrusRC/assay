package scanner

import (
	"fmt"

	"github.com/TyrusRC/assay/internal/core"
)

// ProofLayer represents a verification tier in the proof-based scanning
// pipeline. Higher layers provide stronger confirmation. The design
// mirrors Acunetix's 5-layer confidence model.
type ProofLayer int

const (
	ProofDAST   ProofLayer = iota // Layer 1: DAST response-differential heuristic
	ProofReplay                   // Layer 1b: replay confirms the anomaly persists
	ProofDOM                      // Layer 2: headless browser DOM execution confirms
	ProofIAST                     // Layer 3: IAST sensor confirms payload reached a sink
	ProofOOB                      // Layer 4: out-of-band callback received
	ProofStored                   // Layer 5: stored/second-order injection persists across requests
)

// ProofResult records one layer's verdict on a finding.
type ProofResult struct {
	Layer    ProofLayer
	Evidence string
}

// proofLayerName returns a short human label for a proof layer.
func proofLayerName(l ProofLayer) string {
	switch l {
	case ProofDAST:
		return "dast"
	case ProofReplay:
		return "replay"
	case ProofDOM:
		return "dom"
	case ProofIAST:
		return "iast"
	case ProofOOB:
		return "oob"
	case ProofStored:
		return "stored"
	default:
		return fmt.Sprintf("layer-%d", l)
	}
}

// UpgradeConfidence sets a finding's confidence to the highest level
// that its collected proofs justify, and appends each proof's evidence
// so the report shows exactly which layers confirmed the finding.
//
// Mapping:
//
//	IAST / OOB / Stored  → confirmed  (the payload reached the sink or fired out-of-band)
//	DOM execution         → high       (headless browser observed the effect)
//	Replay                → high       (anomaly persists on re-send)
//	DAST heuristic alone  → medium     (response-differential, no independent confirmation)
func UpgradeConfidence(f *core.Finding, proofs []ProofResult) {
	if len(proofs) == 0 {
		return
	}
	best := confidenceForLayer(ProofDAST)
	for _, p := range proofs {
		c := confidenceForLayer(p.Layer)
		if confidenceRank(c) > confidenceRank(best) {
			best = c
		}
	}
	f.Confidence = best

	for _, p := range proofs {
		if p.Evidence != "" {
			f.Evidence += "\n[proof:" + proofLayerName(p.Layer) + "] " + p.Evidence
		}
	}
}

func confidenceForLayer(l ProofLayer) core.Confidence {
	switch l {
	case ProofIAST, ProofOOB, ProofStored:
		return core.ConfidenceConfirmed
	case ProofDOM, ProofReplay:
		return core.ConfidenceHigh
	default:
		return core.ConfidenceMedium
	}
}

func confidenceRank(c core.Confidence) int {
	switch c {
	case core.ConfidenceConfirmed:
		return 4
	case core.ConfidenceHigh:
		return 3
	case core.ConfidenceMedium:
		return 2
	case core.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// CollectProofs gathers proof results from the scanner's various
// verification sources for a single finding. Called once per finding
// after all detection phases complete.
func CollectProofs(f *core.Finding, iastHits []string, oobInteractions []string, replayConfirmed bool) []ProofResult {
	var proofs []ProofResult

	// Every finding starts with DAST proof (it was detected).
	proofs = append(proofs, ProofResult{Layer: ProofDAST, Evidence: f.Evidence})

	if replayConfirmed {
		proofs = append(proofs, ProofResult{Layer: ProofReplay, Evidence: "anomaly confirmed on replay"})
	}

	for _, hit := range iastHits {
		proofs = append(proofs, ProofResult{Layer: ProofIAST, Evidence: hit})
	}

	for _, interaction := range oobInteractions {
		proofs = append(proofs, ProofResult{Layer: ProofOOB, Evidence: interaction})
	}

	return proofs
}
