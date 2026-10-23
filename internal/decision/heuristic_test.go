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
			name:    "verified sqli",
			text:    "SQL Injection on /api/users param \"id\" [verified]: syntax error near 'OR'",
			wantMin: 0.8,
			wantMax: 1.0,
		},
		{
			name:    "unverified xss",
			text:    "Cross-Site Scripting (XSS) on /search param \"q\": reflected <script>alert(1)</script>",
			wantMin: 0.5,
			wantMax: 0.75,
		},
		{
			name:    "missing header noise",
			text:    "Missing header X-Frame-Options on /login",
			wantMin: 0.0,
			wantMax: 0.35,
		},
		{
			name:    "ssti confirmed",
			text:    "Server-Side Template Injection (SSTI) on /render param \"name\" [verified]: sentinel st12349st123 confirmed",
			wantMin: 0.85,
			wantMax: 1.0,
		},
		{
			name:    "known cve unverified",
			text:    "Known CVE: CVE-2023-24329 in Python",
			wantMin: 0.3,
			wantMax: 0.5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := heuristicScore(tt.text)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("heuristicScore(%q) = %.2f, want [%.2f, %.2f]", tt.text, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestHeuristicAdjudicate(t *testing.T) {
	items := []Item{
		{Key: "f1", Text: "SQL Injection on /api param id [verified]: error"},
		{Key: "f2", Text: "Missing header X-Frame-Options on /"},
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
		t.Errorf("SQLi should score higher than missing header: %.2f vs %.2f", *probs[0], *probs[1])
	}
}
