package protopollution

import (
	"fmt"
	"strings"
)

// PollutionVector is one URL-based attempt to set Object.prototype[key]=value
// through a client-side prototype-pollution source.
type PollutionVector struct {
	// Name identifies the injection syntax (for evidence).
	Name string
	// URL is the target URL carrying the pollution payload.
	URL string
}

// Gadget is a known prototype-pollution gadget: a polluted property that a
// common library or the platform reads and feeds into a dangerous sink. Finding
// one confirms a source→gadget→sink chain rather than a bare source.
type Gadget struct {
	// Property is the Object.prototype key that activates the gadget.
	Property string
	// Sink describes where the polluted value flows.
	Sink string
	// Description explains the gadget.
	Description string
}

// BuildPollutionVectors returns URL payloads that try to pollute
// Object.prototype[key]=value via the documented client-side syntaxes: bracket
// and dotted __proto__ notation, the constructor.prototype chain, and the
// fragment-based equivalents (many SPAs parse location.hash into config).
func BuildPollutionVectors(target, key, value string) []PollutionVector {
	kv := func(prefix string) string { return prefix + "=" + value }
	queries := []struct{ name, frag string }{
		{"bracket __proto__", kv(fmt.Sprintf("__proto__[%s]", key))},
		{"dotted __proto__", kv(fmt.Sprintf("__proto__.%s", key))},
		{"constructor.prototype", kv(fmt.Sprintf("constructor[prototype][%s]", key))},
	}

	vectors := make([]PollutionVector, 0, len(queries)*2)
	for _, q := range queries {
		vectors = append(vectors,
			PollutionVector{Name: "query " + q.name, URL: appendQuery(target, q.frag)},
			PollutionVector{Name: "fragment " + q.name, URL: appendFragment(target, q.frag)},
		)
	}
	return vectors
}

// appendQuery appends a raw query fragment, joining with & if a query exists.
func appendQuery(target, frag string) string {
	sep := "?"
	// Strip any existing fragment so the query stays before the '#'.
	base, hash := splitFragment(target)
	if strings.Contains(base, "?") {
		sep = "&"
	}
	out := base + sep + frag
	if hash != "" {
		out += "#" + hash
	}
	return out
}

// appendFragment appends a raw fragment to the URL.
func appendFragment(target, frag string) string {
	base, _ := splitFragment(target)
	return base + "#" + frag
}

// splitFragment splits a URL into its pre-fragment part and fragment.
func splitFragment(target string) (base, frag string) {
	if i := strings.Index(target, "#"); i >= 0 {
		return target[:i], target[i+1:]
	}
	return target, ""
}

// ReadPrototypeExpr returns a JS expression that reads key off a fresh empty
// object (so it only sees prototype-chain pollution, not own properties) and
// returns it as a string, or "undefined" when unpolluted.
func ReadPrototypeExpr(key string) string {
	return fmt.Sprintf(`(function(){try{var v=({})[%q];return v===undefined?"undefined":String(v);}catch(e){return "undefined";}})()`, key)
}

// ConfirmsPollution reports whether an eval result proves Object.prototype was
// polluted with the expected sentinel value. It tolerates the surrounding
// double quotes some headless eval bridges (e.g. rod) add to string returns.
func ConfirmsPollution(evalResult, expected string) bool {
	s := strings.Trim(strings.TrimSpace(evalResult), `"`)
	if s == "" || s == "undefined" {
		return false
	}
	return s == expected
}

// GadgetCatalog returns well-known client-side prototype-pollution gadgets.
// Each maps a polluted property to the sink it reaches; observing the sink
// after pollution upgrades a finding from "source present" to "exploitable".
func GadgetCatalog() []Gadget {
	return []Gadget{
		{Property: "srcdoc", Sink: "iframe.srcdoc", Description: "Polluted srcdoc rendered into an iframe → HTML/JS execution"},
		{Property: "innerHTML", Sink: "element.innerHTML", Description: "Polluted innerHTML default written to the DOM → XSS"},
		{Property: "src", Sink: "script.src", Description: "Polluted src used as a default script source → remote code load"},
		{Property: "url", Sink: "script.src / fetch", Description: "Polluted url default used for dynamic script/fetch loading"},
		{Property: "html", Sink: "template render", Description: "Polluted html default rendered by templating libraries → XSS"},
		{Property: "transport_url", Sink: "Socket.IO transport", Description: "Polluted transport_url used by client transports → script load"},
	}
}
