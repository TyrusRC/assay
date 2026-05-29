package javareflect

import (
	"strings"
	"testing"
)

func TestGetPayloads_MinCount(t *testing.T) {
	got := GetPayloads()
	if len(got) < 12 {
		t.Errorf("expected at least 12 Java reflection payloads, got %d", len(got))
	}
}

func TestGetPayloads_Shape(t *testing.T) {
	got := GetPayloads()
	if len(got) == 0 {
		t.Fatal("no payloads")
	}
	validImpact := map[Impact]bool{
		ImpactRCE:      true,
		ImpactInfoLeak: true,
		ImpactSSRF:     true,
		ImpactDoS:      true,
	}
	for _, p := range got {
		if p.Value == "" {
			t.Errorf("payload has empty Value")
		}
		if !validImpact[p.Impact] {
			t.Errorf("payload %q has invalid Impact %q", p.Value, p.Impact)
		}
	}
}

func TestGetPayloads_CoverPrimitives(t *testing.T) {
	got := GetPayloads()
	joined := ""
	for _, p := range got {
		joined += p.Value + "\n"
	}
	required := []string{
		"java.lang.Runtime",
		"getRuntime",
		"ProcessBuilder",
		"Class.forName",
		"classLoader",
		"getClass()",
		"getDeclaredMethod",
		"invoke",
		"java.net.URL",     // SSRF surface
		"javax.naming",     // JNDI surface
	}
	for _, r := range required {
		if !strings.Contains(joined, r) {
			t.Errorf("Java reflection bank missing required primitive: %q", r)
		}
	}
}

func TestGetByImpact_Buckets(t *testing.T) {
	for _, imp := range []Impact{ImpactRCE, ImpactInfoLeak, ImpactSSRF} {
		got := GetByImpact(imp)
		if len(got) == 0 {
			t.Errorf("no payloads for impact %q", imp)
		}
	}
}

func TestGetErrorPatterns_NonEmpty(t *testing.T) {
	got := GetErrorPatterns()
	if len(got) < 5 {
		t.Errorf("expected at least 5 Java error patterns, got %d", len(got))
	}
	for _, p := range got {
		lp := strings.ToLower(p)
		if !strings.Contains(lp, "java") &&
			!strings.Contains(lp, "exception") &&
			!strings.Contains(lp, "at sun.") &&
			!strings.Contains(lp, "at jdk.") &&
			!strings.Contains(lp, "tomcat") {
			t.Errorf("error pattern %q is not Java-class", p)
		}
	}
}
