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

func TestQuickProfile_DisablesHeavyPerParamRunners(t *testing.T) {
	p := QuickProfile()
	cases := []struct {
		name string
		on   bool
	}{
		{"EnableNodeJSInject", p.Config.EnableNodeJSInject},
		{"EnableJavaReflect", p.Config.EnableJavaReflect},
		{"EnableFileOps", p.Config.EnableFileOps},
		{"EnableArgInject", p.Config.EnableArgInject},
		{"EnableSolrInject", p.Config.EnableSolrInject},
		{"EnablePHPInject", p.Config.EnablePHPInject},
		{"EnableESI", p.Config.EnableESI},
	}
	for _, c := range cases {
		if c.on {
			t.Errorf("Quick profile expected %s=false, got true", c.name)
		}
	}
	// Passive context detectors must stay on — they share baseline budget.
	if !p.Config.EnableWAFDetect {
		t.Error("Quick profile must keep EnableWAFDetect=true (passive)")
	}
	if !p.Config.EnableXFS {
		t.Error("Quick profile must keep EnableXFS=true (passive)")
	}
}

func TestThoroughProfile_EnablesReconStages(t *testing.T) {
	p := ThoroughProfile()
	if !p.Config.EnableVHostEnum {
		t.Error("Thorough profile expected EnableVHostEnum=true")
	}
	if !p.Config.EnableLongPwdDoS {
		t.Error("Thorough profile expected EnableLongPwdDoS=true")
	}
	if p.Config.VHostMaxRequests < 500 {
		t.Errorf("Thorough profile expected VHostMaxRequests >= 500, got %d", p.Config.VHostMaxRequests)
	}
}

func TestPassiveProfile_Basics(t *testing.T) {
	p := PassiveProfile()
	if p.Name != "passive" {
		t.Errorf("expected name 'passive', got %q", p.Name)
	}
	if p.Description == "" {
		t.Error("expected non-empty description")
	}
	if p.Config == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestPassiveProfile_NoInjections(t *testing.T) {
	p := PassiveProfile()
	cases := []struct {
		name string
		on   bool
	}{
		{"EnableSQLi", p.Config.EnableSQLi},
		{"EnableXSS", p.Config.EnableXSS},
		{"EnableCMDI", p.Config.EnableCMDI},
		{"EnableSSRF", p.Config.EnableSSRF},
		{"EnableLFI", p.Config.EnableLFI},
		{"EnableXXE", p.Config.EnableXXE},
		{"EnableNoSQL", p.Config.EnableNoSQL},
		{"EnableSSTI", p.Config.EnableSSTI},
		{"EnableLDAP", p.Config.EnableLDAP},
		{"EnableXPath", p.Config.EnableXPath},
		{"EnableJNDI", p.Config.EnableJNDI},
		{"EnableESI", p.Config.EnableESI},
		{"EnableSolrInject", p.Config.EnableSolrInject},
		{"EnablePHPInject", p.Config.EnablePHPInject},
		{"EnableJavaReflect", p.Config.EnableJavaReflect},
		{"EnableNodeJSInject", p.Config.EnableNodeJSInject},
		{"EnableArgInject", p.Config.EnableArgInject},
		{"EnableFileOps", p.Config.EnableFileOps},
		{"EnableSecondOrder", p.Config.EnableSecondOrder},
		{"EnableSmuggling", p.Config.EnableSmuggling},
		{"EnableRaceCond", p.Config.EnableRaceCond},
		{"EnableOOB", p.Config.EnableOOB},
	}
	for _, c := range cases {
		if c.on {
			t.Errorf("Passive profile expected %s=false, got true", c.name)
		}
	}
}

func TestPassiveProfile_KeepsPassiveDetectors(t *testing.T) {
	p := PassiveProfile()
	cases := []struct {
		name string
		on   bool
	}{
		{"EnableWAFDetect", p.Config.EnableWAFDetect},
		{"EnableXFS", p.Config.EnableXFS},
		{"EnableSameSiteScript", p.Config.EnableSameSiteScript},
		{"EnableIISTilde", p.Config.EnableIISTilde},
		{"EnableSecHeaders", p.Config.EnableSecHeaders},
		{"EnableExposure", p.Config.EnableExposure},
		{"EnableCloud", p.Config.EnableCloud},
		{"EnableTLS", p.Config.EnableTLS},
		{"EnableTechScan", p.Config.EnableTechScan},
		{"EnableJSDep", p.Config.EnableJSDep},
	}
	for _, c := range cases {
		if !c.on {
			t.Errorf("Passive profile expected %s=true (passive/header-only), got false", c.name)
		}
	}
}

func TestGetProfile_Passive(t *testing.T) {
	p := GetProfile("passive")
	if p.Name != "passive" {
		t.Errorf("expected name 'passive', got %q", p.Name)
	}
	if p.Config.EnableSQLi {
		t.Error("expected EnableSQLi=false in passive profile")
	}
}
