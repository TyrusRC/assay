package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/scanner"
)

// All scan-command flag variables. Declared at package scope so init()
// can bind them to cobra and runScan can read them. Grouped roughly by
// concern: transport / proxy, output, then per-detector toggles.
var (
	timeout     time.Duration
	concurrency int
	headers     []string
	cookies     string
	userAgent   string
	insecure    bool
	data        string
	method      string
	level       int
	risk        int
	jsonOutput  bool
	htmlOutput  bool
	disableOOB  bool
	noDiscovery bool
	storageInj  bool
	chromePath  string
	targetList  string
	templateDir string
	profile     string
	noJSDep     bool
	nvdAPIKey   string
	rateLimit   bool
	noDataExp   bool
	noAdminPath bool
	noAPIVer    bool
	apiSpecURL  string
	noCtypeConf bool
	noSSE       bool
	noGRPCRefl  bool
	h2ResetOpt  bool
	noCSRF      bool
	noTabnab    bool
	redosOpt    bool
	noPromptInj bool
	noXSLT      bool
	noSAMLInj   bool
	noORMLeak   bool
	noTypeJug   bool
	noDepConf   bool
	noTokenEnt  bool
	noCacheDec  bool
	noCachePois bool
	noCSSInj    bool
	noDeser     bool
	noDOMClob   bool
	noEmailInj  bool
	noHPP       bool
	noHTMLInj   bool
	massAssign  bool
	protoPollSrv bool
	noSecondOrd bool
	noSSIInj    bool
	noStorage   bool
	noNuclei    bool
	nucleiTags  string
	nucleiSev   string
	authACookie string
	authBCookie string
	authAHdr    []string
	authBHdr    []string
	idorURL     string
	noPostMsg   bool
)

// applyCLIFlags merges parsed CLI flag state into the internalConfig.
// Returns an error only on flag-value parsing failures (malformed
// header strings); detector toggles never error.
//
// The function is intentionally large and flat: each block reads one
// flag and writes one config field. Splitting it further would obscure
// the 1:1 flag→config mapping that's the only thing readers want.
func applyCLIFlags(internalConfig *scanner.InternalScanConfig) error {
	if templateDir != "" {
		internalConfig.EnableTemplates = true
		internalConfig.TemplatePaths = []string{templateDir}
	}
	if disableOOB {
		internalConfig.EnableOOB = false
	}
	if noDiscovery {
		internalConfig.EnableDiscovery = false
	}
	if storageInj {
		internalConfig.EnableStorageInj = true
	}
	if chromePath != "" {
		internalConfig.ChromePath = chromePath
	}
	if noJSDep {
		internalConfig.EnableJSDep = false
	}
	if rateLimit {
		internalConfig.EnableRateLimit = true
	}
	if noDataExp {
		internalConfig.EnableDataExposure = false
	}
	if noAdminPath {
		internalConfig.EnableAdminPath = false
	}
	if noAPIVer {
		internalConfig.EnableAPIVersion = false
	}
	if apiSpecURL != "" {
		internalConfig.APISpecURL = apiSpecURL
	}
	if noCtypeConf {
		internalConfig.EnableContentType = false
	}
	if noSSE {
		internalConfig.EnableSSE = false
	}
	if noGRPCRefl {
		internalConfig.EnableGRPCReflect = false
	}
	if h2ResetOpt {
		internalConfig.EnableH2Reset = true
	}
	if noCSRF {
		internalConfig.EnableCSRF = false
	}
	if noTabnab {
		internalConfig.EnableTabnabbing = false
	}
	if redosOpt {
		internalConfig.EnableReDoS = true
	}
	if noPromptInj {
		internalConfig.EnablePromptInj = false
	}
	if noXSLT {
		internalConfig.EnableXSLT = false
	}
	if noSAMLInj {
		internalConfig.EnableSAMLInj = false
	}
	if noORMLeak {
		internalConfig.EnableORMLeak = false
	}
	if noTypeJug {
		internalConfig.EnableTypeJuggling = false
	}
	if noDepConf {
		internalConfig.EnableDepConfusion = false
	}
	if noTokenEnt {
		internalConfig.EnableTokenEntropy = false
	}
	if noCacheDec {
		internalConfig.EnableCacheDeception = false
	}
	if noCachePois {
		internalConfig.EnableCachePoisoning = false
	}
	if noCSSInj {
		internalConfig.EnableCSSInj = false
	}
	if noDeser {
		internalConfig.EnableDeser = false
	}
	if noDOMClob {
		internalConfig.EnableDOMClobber = false
	}
	if noEmailInj {
		internalConfig.EnableEmailInj = false
	}
	if noHPP {
		internalConfig.EnableHPP = false
	}
	if noHTMLInj {
		internalConfig.EnableHTMLInj = false
	}
	if massAssign {
		internalConfig.EnableMassAssign = true
	}
	if protoPollSrv {
		internalConfig.EnableProtoPollServer = true
	}
	if noSecondOrd {
		internalConfig.EnableSecondOrder = false
	}
	if noSSIInj {
		internalConfig.EnableSSI = false
	}
	if noStorage {
		internalConfig.EnableStorage = false
	}
	if noPostMsg {
		internalConfig.EnablePostMsg = false
	}

	hdrsA, err := parseHeaderArray(authAHdr)
	if err != nil {
		return fmt.Errorf("--auth-a-header: %w", err)
	}
	internalConfig.AuthA = scanner.AuthState{Cookies: authACookie, Headers: hdrsA}

	hdrsB, err := parseHeaderArray(authBHdr)
	if err != nil {
		return fmt.Errorf("--auth-b-header: %w", err)
	}
	internalConfig.AuthB = scanner.AuthState{Cookies: authBCookie, Headers: hdrsB}

	if idorURL != "" {
		internalConfig.IDORTargetURL = idorURL
	}

	// CLI flag wins over env; missing flag falls back to NVD_API_KEY env.
	// Empty after both → public tier (anonymous, ~5 req/30s).
	if nvdAPIKey != "" {
		internalConfig.NVDAPIKey = nvdAPIKey
	} else if env := os.Getenv("NVD_API_KEY"); env != "" {
		internalConfig.NVDAPIKey = env
	}
	return nil
}
