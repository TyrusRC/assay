package scoring

import "testing"

func TestBaseScore(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8},
	}
	for _, tt := range tests {
		m, err := ParseVector(tt.vector)
		if err != nil {
			t.Fatalf("ParseVector(%q) error: %v", tt.vector, err)
		}
		if got := m.BaseScore(); got != tt.want {
			t.Errorf("BaseScore(%q) = %v, want %v", tt.vector, got, tt.want)
		}
	}
}

func TestParseVector_Invalid(t *testing.T) {
	for _, v := range []string{"", "not-a-vector", "CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"} {
		if _, err := ParseVector(v); err == nil {
			t.Errorf("ParseVector(%q) expected error, got nil", v)
		}
	}
}

func TestRating(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0.0, "None"}, {3.9, "Low"}, {4.0, "Medium"}, {6.9, "Medium"},
		{7.0, "High"}, {8.9, "High"}, {9.0, "Critical"}, {10.0, "Critical"},
	}
	for _, tt := range tests {
		if got := Rating(tt.score); got != tt.want {
			t.Errorf("Rating(%v) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
