package scanner

// Profile represents a pre-configured scan profile.
type Profile struct {
	Name        string
	Description string
	Config      *InternalScanConfig
}

// QuickProfile returns a fast scan profile.
//
// Capped payload count plus the heavier per-param-injection runners
// disabled. Keeps the scan under a minute for a single target while
// preserving the passive-context detectors (WAF / XFS / Same-Site
// Scripting / secheaders) because those don't add measurable budget.
func QuickProfile() *Profile {
	config := DefaultInternalConfig()
	config.MaxPayloadsPerParam = 5
	config.EnableSmuggling = false
	config.EnableBehavior = false
	config.EnableOOB = false
	config.IncludeWAFBypass = false
	config.EnableRaceCond = false
	// Prune the heavier per-param-injection stages added in this series.
	// Their passive equivalents (wafdetect / xfs / samesitescript / iistilde
	// / secheaders / exposure) stay on — they share the baseline GET budget.
	config.EnableNodeJSInject = false
	config.EnableJavaReflect = false
	config.EnableFileOps = false
	config.EnableArgInject = false
	config.EnableSolrInject = false
	config.EnablePHPInject = false
	config.EnableESI = false
	config.EnableRSCInject = false // posts Server-Action bodies; skip for quick
	config.EnableCSPT = false      // fetches linked scripts; skip for quick
	return &Profile{Name: "quick", Description: "Fast scan with reduced payloads and heavy per-param runners disabled", Config: config}
}

// ThoroughProfile returns an aggressive scan profile.
//
// Bumps the per-param payload cap and switches on the recon-class stages
// that DefaultInternalConfig leaves off to keep cheap scans cheap
// (VHost wordlist, long-password DoS). Intended for engagement-class
// scans where total wall time is not the constraint.
func ThoroughProfile() *Profile {
	config := DefaultInternalConfig()
	config.MaxPayloadsPerParam = 100
	config.EnableJWT = true
	config.EnableAuth = true
	config.EnableRaceCond = true
	config.IncludeWAFBypass = true
	config.EnableVHostEnum = true
	config.EnableLongPwdDoS = true
	config.VHostMaxRequests = 500
	return &Profile{Name: "thorough", Description: "Comprehensive scan with all detectors and recon stages enabled", Config: config}
}

// PassiveProfile returns a profile that issues no parameter injections.
//
// Only stages that inspect baseline responses, do header-only analysis,
// or fire small RFC-conformant probes run. Safe for production targets
// where active injection traffic is a contract violation. Useful as a
// first-pass triage before deciding whether to escalate to QuickProfile
// or ThoroughProfile.
//
// Stays on (response-only / header-only / DNS-only / small-budget):
//
//	wafdetect, xfs, samesitescript (DNS), iistilde (6 GETs),
//	secheaders, exposure, cloud, subtakeover, tls, techstack, jsdep,
//	dataexposure, adminpath, apiversion, contenttype, tokenentropy,
//	cachekey, samesitelax, stacktrace.
//
// Disabled (any parameter injection or active reflection probe):
//
//	all *Inject + *FileOps + ESI + RaceCond + Behavior + Smuggling +
//	OOB + RFI + JNDI + LDAP + XPath + SAML + XSLT + Templates.
func PassiveProfile() *Profile {
	config := DefaultInternalConfig()

	// Disable every parameter-injection / active-probe detector.
	config.EnableSQLi = false
	config.EnableXSS = false
	config.EnableCMDI = false
	config.EnableSSRF = false
	config.EnableLFI = false
	config.EnableXXE = false
	config.EnableNoSQL = false
	config.EnableSSTI = false
	config.EnableIDOR = false
	config.EnableRedirect = false
	config.EnableCRLF = false
	config.EnableLDAP = false
	config.EnableXPath = false
	config.EnableHeaderInj = false
	config.EnableCSTI = false
	config.EnableRFI = false
	config.EnableJNDI = false
	config.EnableSmuggling = false
	config.EnableBehavior = false
	config.EnableOOB = false
	config.EnableLogInj = false
	config.EnableFileUpload = false
	config.EnableVerbTamper = false
	config.EnablePathNorm = false
	config.EnableRaceCond = false
	config.EnableCSVInj = false
	config.EnableHostHdr = false
	config.EnableOAuth = false
	config.EnableCSRF = false
	config.EnableTabnabbing = false
	config.EnableCSPT = false
	config.EnableReDoS = false
	config.EnablePromptInj = false
	config.EnableXSLT = false
	config.EnableSAMLInj = false
	config.EnableORMLeak = false
	config.EnableTypeJuggling = false
	config.EnableCSSInj = false
	config.EnableDeser = false
	config.EnableDOMClobber = false
	config.EnableEmailInj = false
	config.EnableHPP = false
	config.EnableHTMLInj = false
	config.EnableMassAssign = false
	config.EnableProtoPoll = false
	config.EnableProtoPollServer = false
	config.EnableSecondOrder = false
	config.EnableSSI = false
	config.EnableStorageInj = false
	config.EnableSessionFixation = false
	config.EnableESI = false
	config.EnableSolrInject = false
	config.EnablePHPInject = false
	config.EnableJavaReflect = false
	config.EnableNodeJSInject = false
	config.EnableArgInject = false
	config.EnableFileOps = false
	// rscinject fires Server-Action POSTs against the target — disable.
	// webauthn + http3desync are pure discovery (wordlist GETs / single
	// HEAD respectively) and stay on.
	config.EnableRSCInject = false

	return &Profile{Name: "passive", Description: "Passive-only scan — no parameter injections; safe for production", Config: config}
}

// GetProfile returns a profile by name. Unknown names fall back to the
// default ("normal") configuration.
func GetProfile(name string) *Profile {
	switch name {
	case "quick":
		return QuickProfile()
	case "thorough":
		return ThoroughProfile()
	case "passive":
		return PassiveProfile()
	default:
		return &Profile{Name: "normal", Description: "Standard scan", Config: DefaultInternalConfig()}
	}
}
