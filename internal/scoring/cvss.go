// Package scoring computes CVSS v3.1 base scores and supplies representative
// default vectors for findings that carry no externally-provided score.
package scoring

import (
	"fmt"
	"math"
	"strings"
)

// Metrics is a parsed CVSS v3.1 base-metric group.
type Metrics struct {
	AV, AC, PR, UI, S, C, I, A string
}

var (
	avW  = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	acW  = map[string]float64{"L": 0.77, "H": 0.44}
	uiW  = map[string]float64{"N": 0.85, "R": 0.62}
	ciaW = map[string]float64{"H": 0.56, "L": 0.22, "N": 0.00}
	prU  = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prC  = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
)

// ParseVector parses a CVSS v3.1 vector string into Metrics. It requires the
// eight base metrics (AV, AC, PR, UI, S, C, I, A) with valid values.
func ParseVector(vector string) (Metrics, error) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) == 0 || !strings.EqualFold(parts[0], "CVSS:3.1") {
		return Metrics{}, fmt.Errorf("not a CVSS v3.1 vector: %q", vector)
	}
	kv := make(map[string]string)
	for _, p := range parts[1:] {
		bits := strings.SplitN(p, ":", 2)
		if len(bits) == 2 {
			kv[strings.ToUpper(bits[0])] = strings.ToUpper(bits[1])
		}
	}
	m := Metrics{
		AV: kv["AV"], AC: kv["AC"], PR: kv["PR"], UI: kv["UI"],
		S: kv["S"], C: kv["C"], I: kv["I"], A: kv["A"],
	}
	if _, ok := avW[m.AV]; !ok {
		return Metrics{}, fmt.Errorf("invalid AV in %q", vector)
	}
	if _, ok := acW[m.AC]; !ok {
		return Metrics{}, fmt.Errorf("invalid AC in %q", vector)
	}
	if _, ok := uiW[m.UI]; !ok {
		return Metrics{}, fmt.Errorf("invalid UI in %q", vector)
	}
	if m.S != "U" && m.S != "C" {
		return Metrics{}, fmt.Errorf("invalid S in %q", vector)
	}
	if _, ok := ciaW[m.C]; !ok {
		return Metrics{}, fmt.Errorf("invalid C in %q", vector)
	}
	if _, ok := ciaW[m.I]; !ok {
		return Metrics{}, fmt.Errorf("invalid I in %q", vector)
	}
	if _, ok := ciaW[m.A]; !ok {
		return Metrics{}, fmt.Errorf("invalid A in %q", vector)
	}
	prTable := prU
	if m.S == "C" {
		prTable = prC
	}
	if _, ok := prTable[m.PR]; !ok {
		return Metrics{}, fmt.Errorf("invalid PR in %q", vector)
	}
	return m, nil
}

// BaseScore computes the CVSS v3.1 base score (0.0-10.0).
func (m Metrics) BaseScore() float64 {
	prTable := prU
	scopeChanged := m.S == "C"
	if scopeChanged {
		prTable = prC
	}
	iscBase := 1 - ((1 - ciaW[m.C]) * (1 - ciaW[m.I]) * (1 - ciaW[m.A]))
	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}
	exploit := 8.22 * avW[m.AV] * acW[m.AC] * prTable[m.PR] * uiW[m.UI]
	if impact <= 0 {
		return 0.0
	}
	var raw float64
	if scopeChanged {
		raw = math.Min(1.08*(impact+exploit), 10)
	} else {
		raw = math.Min(impact+exploit, 10)
	}
	return roundUp(raw)
}

// roundUp implements the CVSS v3.1 specification's round-up-to-one-decimal.
func roundUp(input float64) float64 {
	i := int(math.Round(input * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}

// Rating maps a base score to the CVSS qualitative severity rating.
func Rating(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score > 0.0:
		return "Low"
	default:
		return "None"
	}
}
