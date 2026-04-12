package scanner

// Profile represents a pre-configured scan profile.
type Profile struct {
	Name        string
	Description string
	Config      *InternalScanConfig
}

// QuickProfile returns a fast scan profile.
func QuickProfile() *Profile {
	config := DefaultInternalConfig()
	config.MaxPayloadsPerParam = 5
	config.EnableSmuggling = false
	config.EnableBehavior = false
	config.EnableOOB = false
	config.IncludeWAFBypass = false
	config.EnableRaceCond = false
	return &Profile{Name: "quick", Description: "Fast scan with reduced payloads", Config: config}
}

// ThoroughProfile returns an aggressive scan profile.
func ThoroughProfile() *Profile {
	config := DefaultInternalConfig()
	config.MaxPayloadsPerParam = 100
	config.EnableJWT = true
	config.EnableAuth = true
	config.EnableRaceCond = true
	config.IncludeWAFBypass = true
	return &Profile{Name: "thorough", Description: "Comprehensive scan with all detectors", Config: config}
}

// GetProfile returns a profile by name.
func GetProfile(name string) *Profile {
	switch name {
	case "quick":
		return QuickProfile()
	case "thorough":
		return ThoroughProfile()
	default:
		return &Profile{Name: "normal", Description: "Standard scan", Config: DefaultInternalConfig()}
	}
}
