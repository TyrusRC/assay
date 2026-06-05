package protopollution

import (
	"strings"
	"testing"
)

func TestBuildPollutionVectors_CoversKnownSyntaxes(t *testing.T) {
	vs := BuildPollutionVectors("https://app.test/page", "assayPP", "POLLUTED")
	if len(vs) == 0 {
		t.Fatal("expected pollution vectors")
	}
	joined := ""
	for _, v := range vs {
		if v.URL == "" || v.Name == "" {
			t.Errorf("vector missing fields: %+v", v)
		}
		joined += v.URL + "\n"
	}
	// Must include bracket, dotted, constructor, and hash-based syntaxes.
	wants := []string{
		"__proto__[assayPP]=POLLUTED",
		"__proto__.assayPP=POLLUTED",
		"constructor[prototype][assayPP]=POLLUTED",
		"#",
	}
	for _, w := range wants {
		if !strings.Contains(joined, w) {
			t.Errorf("expected a vector containing %q; got:\n%s", w, joined)
		}
	}
}

func TestBuildPollutionVectors_PreservesExistingQuery(t *testing.T) {
	vs := BuildPollutionVectors("https://app.test/p?x=1", "k", "v")
	foundQuery := false
	for _, v := range vs {
		if strings.HasPrefix(v.Name, "query ") && strings.Contains(v.URL, "__proto__[k]=v") {
			foundQuery = true
			// query-based vector should join with & after the existing query
			if !strings.Contains(v.URL, "?x=1&") {
				t.Errorf("query vector should append with &: %s", v.URL)
			}
		}
		if strings.HasPrefix(v.Name, "fragment ") && !strings.Contains(v.URL, "#") {
			t.Errorf("fragment vector should contain #: %s", v.URL)
		}
	}
	if !foundQuery {
		t.Error("expected a bracket query vector")
	}
}

func TestReadPrototypeExpr_ReferencesKey(t *testing.T) {
	expr := ReadPrototypeExpr("myKey")
	if !strings.Contains(expr, "myKey") {
		t.Errorf("expr should reference the key: %s", expr)
	}
	// Must read from a fresh empty object's prototype chain, not a global.
	if !strings.Contains(expr, "{}") {
		t.Errorf("expr should probe ({})[key]: %s", expr)
	}
}

func TestConfirmsPollution(t *testing.T) {
	if !ConfirmsPollution("POLLUTED", "POLLUTED") {
		t.Error("equal values should confirm pollution")
	}
	if ConfirmsPollution("", "POLLUTED") {
		t.Error("empty eval result must not confirm")
	}
	if ConfirmsPollution("undefined", "POLLUTED") {
		t.Error("'undefined' must not confirm")
	}
	if ConfirmsPollution("other", "POLLUTED") {
		t.Error("mismatched value must not confirm")
	}
}

func TestGadgetCatalog_WellFormed(t *testing.T) {
	gs := GadgetCatalog()
	if len(gs) == 0 {
		t.Fatal("expected a non-empty gadget catalog")
	}
	seen := map[string]bool{}
	for _, g := range gs {
		if g.Property == "" || g.Sink == "" || g.Description == "" {
			t.Errorf("gadget missing fields: %+v", g)
		}
		if seen[g.Property] {
			t.Errorf("duplicate gadget property %q", g.Property)
		}
		seen[g.Property] = true
	}
}
