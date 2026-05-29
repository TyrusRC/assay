package wafdetect

import (
	"net/http"
	"strings"
	"testing"
)

func TestFingerprints_NonEmpty(t *testing.T) {
	got := Fingerprints()
	if len(got) < 12 {
		t.Errorf("expected at least 12 WAF fingerprints, got %d", len(got))
	}
}

func TestFingerprints_CoverCommonVendors(t *testing.T) {
	required := []string{
		"Cloudflare",
		"Akamai",
		"AWS WAF",
		"Imperva",
		"F5 BIG-IP ASM",
		"ModSecurity",
		"Sucuri",
		"Wallarm",
		"FortiWeb",
		"Barracuda",
		"Citrix NetScaler",
		"Azure Front Door",
	}
	got := Fingerprints()
	seen := make(map[string]bool, len(got))
	for _, fp := range got {
		seen[fp.Vendor] = true
	}
	for _, r := range required {
		if !seen[r] {
			t.Errorf("missing required WAF fingerprint: %s", r)
		}
	}
}

func TestFingerprints_HaveAtLeastOneTell(t *testing.T) {
	for _, fp := range Fingerprints() {
		if fp.Vendor == "" {
			t.Errorf("fingerprint has empty Vendor")
		}
		if len(fp.HeaderTells) == 0 && len(fp.CookieTells) == 0 && len(fp.BodyTells) == 0 {
			t.Errorf("fingerprint %s has no tells (Header/Cookie/Body)", fp.Vendor)
		}
	}
}

func TestDetect_CloudflareViaServerHeader(t *testing.T) {
	resp := newResp(http.Header{
		"Server":      []string{"cloudflare"},
		"Cf-Ray":      []string{"abc123-IAD"},
		"Cf-Cache-Status": []string{"HIT"},
	}, 200, "")
	got := Detect(resp, nil)
	if len(got) == 0 {
		t.Fatal("expected Cloudflare match, got none")
	}
	if !containsVendor(got, "Cloudflare") {
		t.Errorf("expected Cloudflare in matches, got %v", vendorList(got))
	}
}

func TestDetect_AWSWAFViaXAmzCfId(t *testing.T) {
	resp := newResp(http.Header{
		"X-Amzn-Requestid": []string{"abc"},
		"X-Amzn-Errortype": []string{"WAFBlockedException"},
	}, 403, "")
	got := Detect(resp, nil)
	if !containsVendor(got, "AWS WAF") {
		t.Errorf("expected AWS WAF, got %v", vendorList(got))
	}
}

func TestDetect_AkamaiViaXAkamaiTransformed(t *testing.T) {
	resp := newResp(http.Header{
		"Server":              []string{"AkamaiGHost"},
		"X-Akamai-Transformed": []string{"9 abc"},
	}, 403, "")
	got := Detect(resp, nil)
	if !containsVendor(got, "Akamai") {
		t.Errorf("expected Akamai, got %v", vendorList(got))
	}
}

func TestDetect_ImpervaViaIncapCookie(t *testing.T) {
	resp := newResp(http.Header{
		"Set-Cookie": []string{"visid_incap_12345=abc; Path=/"},
	}, 200, "")
	got := Detect(resp, nil)
	if !containsVendor(got, "Imperva") {
		t.Errorf("expected Imperva, got %v", vendorList(got))
	}
}

func TestDetect_ModSecurityViaBodySignature(t *testing.T) {
	body := []byte("<html><h1>Not Acceptable!</h1><p>Mod_Security blocked your request</p></html>")
	resp := newResp(http.Header{
		"Server": []string{"Apache"},
	}, 406, "")
	got := Detect(resp, body)
	if !containsVendor(got, "ModSecurity") {
		t.Errorf("expected ModSecurity, got %v", vendorList(got))
	}
}

func TestDetect_NoMatchOnPlainNginx(t *testing.T) {
	resp := newResp(http.Header{
		"Server": []string{"nginx/1.18.0"},
	}, 200, "")
	got := Detect(resp, []byte("<html><body>Hello world</body></html>"))
	if len(got) != 0 {
		t.Errorf("expected no WAF matches on plain nginx, got %v", vendorList(got))
	}
}

func TestDetect_NilResponseSafe(t *testing.T) {
	if got := Detect(nil, nil); got != nil {
		t.Errorf("expected nil for nil response, got %v", got)
	}
}

func TestMatchHasConfidence(t *testing.T) {
	resp := newResp(http.Header{
		"Server": []string{"cloudflare"},
	}, 200, "")
	got := Detect(resp, nil)
	if len(got) == 0 {
		t.Fatal("expected at least one match")
	}
	for _, m := range got {
		if m.Confidence < 1 || m.Confidence > 100 {
			t.Errorf("match %s has invalid Confidence %d (want 1-100)", m.Vendor, m.Confidence)
		}
		if m.Evidence == "" {
			t.Errorf("match %s has empty Evidence", m.Vendor)
		}
	}
}

// --- helpers ---

func newResp(h http.Header, status int, _ string) *http.Response {
	return &http.Response{Header: h, StatusCode: status}
}

func containsVendor(matches []Match, vendor string) bool {
	for _, m := range matches {
		if strings.EqualFold(m.Vendor, vendor) {
			return true
		}
	}
	return false
}

func vendorList(matches []Match) []string {
	var out []string
	for _, m := range matches {
		out = append(out, m.Vendor)
	}
	return out
}
