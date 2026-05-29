package solrinject

import (
	"strings"
	"testing"
)

func TestGetPayloads_MinCount(t *testing.T) {
	got := GetPayloads()
	if len(got) < 12 {
		t.Errorf("expected at least 12 Solr injection payloads, got %d", len(got))
	}
}

func TestGetPayloads_ShapeAndImpact(t *testing.T) {
	got := GetPayloads()
	if len(got) == 0 {
		t.Fatal("no payloads to assert on")
	}
	validImpact := map[Impact]bool{
		ImpactRCE:      true,
		ImpactFileRead: true,
		ImpactSSRF:     true,
		ImpactInfoLeak: true,
	}
	for _, p := range got {
		if p.Value == "" {
			t.Errorf("payload has empty Value")
		}
		if p.Technique == "" {
			t.Errorf("payload %q has empty Technique", p.Value)
		}
		if !validImpact[p.Impact] {
			t.Errorf("payload %q has invalid Impact %q", p.Value, p.Impact)
		}
	}
}

func TestGetPayloads_CoverKeyTechniques(t *testing.T) {
	got := GetPayloads()
	joined := ""
	for _, p := range got {
		joined += p.Value + "\n"
	}
	required := []string{
		"v.template",                 // Velocity template parameter
		"shards=",                    // SSRF via shards
		"stream.url=",                // SSRF via stream
		"stream.body=",               // arbitrary body injection
		"{!xmlparser",                // XXE via xmlparser local-param
		"q={!join",                   // join filter
		"qt=/",                       // request handler swap
		"dataConfig=",                // DataImportHandler config swap (RCE)
		"jndi:",                      // Solr Log4Shell vector
		"#set",                       // Velocity #set RCE chain
		"Runtime.getRuntime",         // Velocity Java reflection RCE
		"#httpclient",                // SolrCloud httpclient SSRF
	}
	for _, r := range required {
		if !strings.Contains(joined, r) {
			t.Errorf("Solr injection bank missing required technique: %q", r)
		}
	}
}

func TestGetByImpact_Buckets(t *testing.T) {
	for _, imp := range []Impact{ImpactRCE, ImpactSSRF, ImpactFileRead, ImpactInfoLeak} {
		got := GetByImpact(imp)
		if len(got) == 0 {
			t.Errorf("no payloads for impact %q", imp)
		}
		for _, p := range got {
			if p.Impact != imp {
				t.Errorf("GetByImpact(%q) returned %q", imp, p.Impact)
			}
		}
	}
}

func TestGetErrorPatterns_NonEmpty(t *testing.T) {
	got := GetErrorPatterns()
	if len(got) < 4 {
		t.Errorf("expected at least 4 Solr error fingerprints, got %d", len(got))
	}
	// Each pattern must mention Solr or a Solr-class component.
	for _, p := range got {
		lp := strings.ToLower(p)
		if !strings.Contains(lp, "solr") &&
			!strings.Contains(lp, "lucene") &&
			!strings.Contains(lp, "velocity") {
			t.Errorf("error pattern %q does not reference solr/lucene/velocity", p)
		}
	}
}
