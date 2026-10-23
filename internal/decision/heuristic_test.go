package decision

import "testing"

func TestHeuristicScore(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		wantMin float64
		wantMax float64
	}{
		{
			name:    "verified sqli critical",
			text:    `SQL Injection on http://x param "id" [critical,confirmed,verified-by-replay,tool:sqli-detector]: syntax error near 'OR'`,
			wantMin: 0.90,
			wantMax: 1.0,
		},
		{
			name:    "unverified xss medium",
			text:    `Cross-Site Scripting (XSS) on http://x param "q" [high,low,unverified,tool:xss-detector]: <script>alert(1)</script>`,
			wantMin: 0.35,
			wantMax: 0.55,
		},
		{
			name:    "verified ssti",
			text:    `Server-Side Template Injection (SSTI) on http://x param "name" [high,confirmed,verified-by-replay,tool:ssti-detector]: sentinel st12349st123`,
			wantMin: 0.90,
			wantMax: 1.0,
		},
		{
			name:    "css injection noise",
			text:    `CSS Injection on http://x param "p" [medium,low,unverified,tool:cssinj-detector]: background:url(http://evil)`,
			wantMin: 0.10,
			wantMax: 0.35,
		},
		{
			name:    "hpp noise",
			text:    `HTTP Parameter Pollution on http://x param "p" [medium,low,unverified,tool:hpp-detector]: duplicate param`,
			wantMin: 0.10,
			wantMax: 0.35,
		},
		{
			name:    "ssi injection noise",
			text:    `SSI Injection on http://x param "p" [high,low,unverified,tool:ssi-detector]: exec cmd=echo`,
			wantMin: 0.10,
			wantMax: 0.35,
		},
		{
			name:    "missing header deep noise",
			text:    `Missing header X-Frame-Options on http://x param "" [low,low,unverified]: no clickjacking protection`,
			wantMin: 0.0,
			wantMax: 0.20,
		},
		{
			name:    "known cve unverified",
			text:    `Known CVE: CVE-2023-24329 in Python on http://x param "" [high,low,unverified,tool:techstack-cve-correlator]`,
			wantMin: 0.15,
			wantMax: 0.40,
		},
		{
			name:    "email injection noise",
			text:    `Email Header Injection on http://x param "p" [medium,low,unverified,tool:emailinj-detector]: cc header injected`,
			wantMin: 0.10,
			wantMax: 0.35,
		},
		{
			name:    "unverified xss high severity",
			text:    `Cross-Site Scripting (XSS) on http://x param "q" [high,high,unverified,tool:xss-detector]: <script>alert(1)</script> reflected in response body`,
			wantMin: 0.40,
			wantMax: 0.65,
		},
		{
			name:    "verified xss",
			text:    `Cross-Site Scripting (XSS) on http://x param "q" [high,confirmed,verified-by-replay,tool:xss-detector]: <script>alert(1)</script> executed in DOM`,
			wantMin: 0.85,
			wantMax: 1.0,
		},
		{
			name:    "reverse tabnabbing noise",
			text:    `Reverse Tabnabbing on http://x param "" [low,low,unverified,tool:link-checker]: target=_blank without rel=noopener`,
			wantMin: 0.0,
			wantMax: 0.30,
		},
		{
			name:    "content spoofing noise",
			text:    `Content Spoofing on http://x param "msg" [low,low,unverified,tool:reflect-detector]: text reflected in page`,
			wantMin: 0.0,
			wantMax: 0.30,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := heuristicScore(tt.text)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("heuristicScore() = %.3f, want [%.2f, %.2f]\n  text: %s", got, tt.wantMin, tt.wantMax, tt.text)
			}
		})
	}
}

func TestHeuristicSeparation(t *testing.T) {
	real := heuristicScore(`SQL Injection on http://x param "id" [critical,confirmed,verified-by-replay,tool:sqli-detector]: syntax error PostgreSQL`)
	noise := heuristicScore(`CSS Injection on http://x param "p" [medium,low,unverified,tool:cssinj-detector]: background:url()`)

	gap := real - noise
	if gap < 0.50 {
		t.Errorf("real(%.3f) - noise(%.3f) = %.3f, want gap >= 0.50", real, noise, gap)
	}
}

func TestImpactQualifierCoversLowValue(t *testing.T) {
	lowValueClasses := []string{
		"CSS Injection", "Email Header Injection",
		"HTTP Parameter Pollution", "HTML Injection",
		"SSI Injection", "Format String Injection",
		"DOM Clobbering", "Reverse Tabnabbing",
		"Content Spoofing", "Text Injection",
	}
	for _, cls := range lowValueClasses {
		q := ImpactQualifier(cls)
		if q == "" {
			t.Errorf("ImpactQualifier(%q) returned empty — must cover all low-value classes", cls)
		}
	}
}

func TestImpactQualifierNonNoise(t *testing.T) {
	realClasses := []string{
		"SQL Injection", "Cross-Site Scripting (XSS)",
		"Server-Side Template Injection (SSTI)", "Command Injection",
	}
	for _, cls := range realClasses {
		q := ImpactQualifier(cls)
		if q != "" {
			t.Errorf("ImpactQualifier(%q) = %q, want empty for real finding classes", cls, q)
		}
	}
}

func TestHeuristicAdjudicate(t *testing.T) {
	items := []Item{
		{Key: "f1", Text: `SQL Injection on http://x param "id" [critical,confirmed,verified-by-replay]: error`},
		{Key: "f2", Text: `CSS Injection on http://x param "p" [medium,low,unverified]: style`},
	}
	probs := heuristicAdjudicate(items)
	if len(probs) != len(items) {
		t.Fatalf("expected %d probs, got %d", len(items), len(probs))
	}
	for i, p := range probs {
		if p == nil {
			t.Errorf("item %d: expected non-nil probability", i)
		}
	}
	if *probs[0] <= *probs[1] {
		t.Errorf("SQLi should score higher than CSS injection: %.3f vs %.3f", *probs[0], *probs[1])
	}
}
