package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TyrusRC/assay/internal/scanner"
)

// All scan-command flag variables. Declared at package scope so init()
// can bind them to cobra and runScan can read them. Grouped roughly by
// concern: transport / proxy, output, then per-detector toggles.
var (
	timeout              time.Duration
	concurrency          int
	onlyTests            []string
	onlyParams           []string
	headers              []string
	cookies              string
	userAgent            string
	insecure             bool
	data                 string
	method               string
	level                int
	risk                 int
	jsonOutput           bool
	htmlOutput           bool
	formatList           string
	outputDir            string
	failOn               string
	disableOOB           bool
	noDiscovery          bool
	storageInj           bool
	chromePath           string
	crawl                bool
	crawlStates          bool
	crawlDepth           int
	crawlPages           int
	submitForms          bool
	configPath           string
	cfgFileTargets       []string
	loginURL             string
	loginUser            string
	loginPass            string
	loginUserField       string
	loginPassField       string
	loginSuccess         string
	loginHeadless        bool
	lsrPath              string
	baselinePath         string
	failOnNew            bool
	targetList           string
	templateDirs         []string
	profile              string
	noJSDep              bool
	nvdAPIKey            string
	rateLimit            bool
	noDataExp            bool
	noAdminPath          bool
	noAPIVer             bool
	apiSpecURL           string
	noCtypeConf          bool
	noSSE                bool
	noGRPCRefl           bool
	h2ResetOpt           bool
	h2ContinueOpt        bool
	h2MadeResetOpt       bool
	noCSRF               bool
	noTabnab             bool
	noCSPT               bool
	noBAC                bool
	redosOpt             bool
	noPromptInj          bool
	noXSLT               bool
	noSAMLInj            bool
	noORMLeak            bool
	noTypeJug            bool
	noDepConf            bool
	noTokenEnt           bool
	noCacheDec           bool
	noCachePois          bool
	noCSSInj             bool
	noDeser              bool
	noDOMClob            bool
	noEmailInj           bool
	noHPP                bool
	noHTMLInj            bool
	massAssign           bool
	protoPollSrv         bool
	noSecondOrd          bool
	storedXSSOpt         bool
	noSSIInj             bool
	noStorage            bool
	noNuclei             bool
	internalOnly         bool
	nucleiTags           string
	nucleiSev            string
	authACookie          string
	authBCookie          string
	authAHdr             []string
	authBHdr             []string
	idorURL              string
	noPostMsg            bool
	verifyFindings       bool
	complianceSpec       string
	githubRepo           string
	jiraURL              string
	jiraProject          string
	exportMinSev         string
	exportDryRun         bool
	noScope              bool
	scopeHosts           []string
	includePaths         []string
	excludePaths         []string
	noDefaultExcludes    bool
	ratePerSec           float64
	sessionCheckURL      string
	sessionCheckInterval time.Duration
	checkpointPath       string
	resumePath           string
	dryRun               bool
	iastEnabled          bool
	iastAddr             string
	minConfidence        string
	coveragePath         string
	fpDatabasePath       string
	incremental          bool
)

// applyCLIFlags merges parsed CLI flag state into the internalConfig.
// Returns an error only on flag-value parsing failures (malformed
// header strings); detector toggles never error.
//
// The function is intentionally large and flat: each block reads one
// flag and writes one config field. Splitting it further would obscure
// the 1:1 flag→config mapping that's the only thing readers want.
func applyCLIFlags(internalConfig *scanner.InternalScanConfig) error {
	if len(onlyTests) > 0 {
		internalConfig.OnlyTests = onlyTests
	}
	if len(onlyParams) > 0 {
		internalConfig.OnlyParams = onlyParams
	}
	if len(onlyTests) > 0 {
		// Focused test mode: skip templates entirely.
		internalConfig.EnableTemplates = false
	} else if len(templateDirs) > 0 {
		internalConfig.EnableTemplates = true
		internalConfig.TemplatePaths = templateDirs
	} else {
		internalConfig.TemplatePaths = discoverTemplatePaths()
		if len(internalConfig.TemplatePaths) > 0 {
			internalConfig.EnableTemplates = true
		}
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
	if lsrPath != "" {
		internalConfig.LSRPath = lsrPath
	}
	if crawl {
		internalConfig.EnableSPACrawl = true
		internalConfig.CrawlMaxDepth = crawlDepth
		internalConfig.CrawlMaxPages = crawlPages
	}
	if crawlStates {
		internalConfig.EnableStateCrawl = true
		if crawlPages > 0 {
			internalConfig.CrawlMaxPages = crawlPages
		}
	}
	if submitForms {
		internalConfig.SubmitForms = true
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
	if h2ContinueOpt {
		internalConfig.EnableH2Continue = true
	}
	if h2MadeResetOpt {
		internalConfig.EnableH2MadeReset = true
	}
	if noCSRF {
		internalConfig.EnableCSRF = false
	}
	if noTabnab {
		internalConfig.EnableTabnabbing = false
	}
	if noCSPT {
		internalConfig.EnableCSPT = false
	}
	if noBAC {
		internalConfig.EnableBAC = false
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
	if storedXSSOpt || level >= 3 {
		internalConfig.EnableStoredXSS = true
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

	if iastEnabled {
		internalConfig.EnableIAST = true
		internalConfig.IASTCallbackAddr = iastAddr
	}
	return nil
}

// discoverTemplatePaths returns template directories that exist on disk.
// Checked in order:
//  1. ASSAY_TEMPLATES env var (os.PathListSeparator-separated)
//  2. ~/.local/nuclei-templates (nuclei's default store)
//  3. ~/nuclei-templates (legacy nuclei location)
//  4. ~/.local/share/assay/custom-nuclei-templates/templates
//     (TyrusRC/custom-nuclei-templates clone — ships with Assay)
func discoverTemplatePaths() []string {
	if env := os.Getenv("ASSAY_TEMPLATES"); env != "" {
		return filepath.SplitList(env)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	candidates := []string{
		filepath.Join(home, ".local", "nuclei-templates"),
		filepath.Join(home, "nuclei-templates"),
		filepath.Join(home, ".local", "share", "assay", "custom-nuclei-templates", "templates"),
	}

	var found []string
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.IsDir() {
			found = append(found, c)
		}
	}
	return found
}
