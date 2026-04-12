package scanner

import "testing"

func TestQuickProfile(t *testing.T) {
	p := QuickProfile()

	if p.Name != "quick" {
		t.Errorf("expected name 'quick', got %q", p.Name)
	}
	if p.Description == "" {
		t.Error("expected non-empty description")
	}
	if p.Config == nil {
		t.Fatal("expected non-nil config")
	}
	if p.Config.MaxPayloadsPerParam != 5 {
		t.Errorf("expected MaxPayloadsPerParam=5, got %d", p.Config.MaxPayloadsPerParam)
	}
	if p.Config.EnableSmuggling {
		t.Error("expected EnableSmuggling=false")
	}
	if p.Config.EnableBehavior {
		t.Error("expected EnableBehavior=false")
	}
	if p.Config.EnableOOB {
		t.Error("expected EnableOOB=false")
	}
	if p.Config.IncludeWAFBypass {
		t.Error("expected IncludeWAFBypass=false")
	}
	if p.Config.EnableRaceCond {
		t.Error("expected EnableRaceCond=false")
	}
	// Verify quick profile still enables core detectors from defaults.
	if !p.Config.EnableSQLi {
		t.Error("expected EnableSQLi=true (inherited from default)")
	}
	if !p.Config.EnableXSS {
		t.Error("expected EnableXSS=true (inherited from default)")
	}
}

func TestThoroughProfile(t *testing.T) {
	p := ThoroughProfile()

	if p.Name != "thorough" {
		t.Errorf("expected name 'thorough', got %q", p.Name)
	}
	if p.Description == "" {
		t.Error("expected non-empty description")
	}
	if p.Config == nil {
		t.Fatal("expected non-nil config")
	}
	if p.Config.MaxPayloadsPerParam != 100 {
		t.Errorf("expected MaxPayloadsPerParam=100, got %d", p.Config.MaxPayloadsPerParam)
	}
	if !p.Config.EnableJWT {
		t.Error("expected EnableJWT=true")
	}
	if !p.Config.EnableAuth {
		t.Error("expected EnableAuth=true")
	}
	if !p.Config.EnableRaceCond {
		t.Error("expected EnableRaceCond=true")
	}
	if !p.Config.IncludeWAFBypass {
		t.Error("expected IncludeWAFBypass=true")
	}
	// Verify thorough profile keeps all default detectors enabled.
	if !p.Config.EnableSQLi {
		t.Error("expected EnableSQLi=true")
	}
	if !p.Config.EnableXSS {
		t.Error("expected EnableXSS=true")
	}
}

func TestGetProfile_Quick(t *testing.T) {
	p := GetProfile("quick")
	if p.Name != "quick" {
		t.Errorf("expected name 'quick', got %q", p.Name)
	}
	if p.Config.MaxPayloadsPerParam != 5 {
		t.Errorf("expected MaxPayloadsPerParam=5, got %d", p.Config.MaxPayloadsPerParam)
	}
}

func TestGetProfile_Thorough(t *testing.T) {
	p := GetProfile("thorough")
	if p.Name != "thorough" {
		t.Errorf("expected name 'thorough', got %q", p.Name)
	}
	if p.Config.MaxPayloadsPerParam != 100 {
		t.Errorf("expected MaxPayloadsPerParam=100, got %d", p.Config.MaxPayloadsPerParam)
	}
}

func TestGetProfile_Default(t *testing.T) {
	p := GetProfile("unknown")
	if p.Name != "normal" {
		t.Errorf("expected name 'normal', got %q", p.Name)
	}
	if p.Config.MaxPayloadsPerParam != 30 {
		t.Errorf("expected MaxPayloadsPerParam=30 (default), got %d", p.Config.MaxPayloadsPerParam)
	}
}

func TestGetProfile_EmptyString(t *testing.T) {
	p := GetProfile("")
	if p.Name != "normal" {
		t.Errorf("expected name 'normal' for empty input, got %q", p.Name)
	}
}
