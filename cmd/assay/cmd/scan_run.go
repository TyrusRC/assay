// scan_run.go — scan execution: runScan (the cobra RunE handler),
// printDryRun, and adjudicateFindings.
package cmd

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/decision"
	"github.com/TyrusRC/assay/internal/reporting"
	"github.com/TyrusRC/assay/internal/scanner"
	"github.com/TyrusRC/assay/internal/scope"
	"github.com/TyrusRC/assay/internal/session"
	"github.com/spf13/cobra"
)
func printDryRun(targets []string, cfg *scanner.InternalScanConfig) {
	w := os.Stderr
	fmt.Fprintln(w, "=== DRY RUN — no traffic will be sent ===")
	fmt.Fprintf(w, "Targets (%d):\n", len(targets))
	for _, t := range targets {
		fmt.Fprintf(w, "  %s\n", t)
	}
	fmt.Fprintf(w, "Profile: %s\n", profile)
	fmt.Fprintf(w, "Level: %d  Risk: %d\n", level, risk)
	fmt.Fprintf(w, "Rate limit: %.0f req/s\n", cfg.RateLimitPerSec)
	if cfg.Scope != nil {
		fmt.Fprintln(w, "Scope: ON (target host(s))")
	} else {
		fmt.Fprintln(w, "Scope: OFF")
	}
	fmt.Fprintln(w, "\nEnabled detectors:")
	v := reflect.ValueOf(cfg).Elem()
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if strings.HasPrefix(f.Name, "Enable") && f.Type.Kind() == reflect.Bool && v.Field(i).Bool() {
			fmt.Fprintf(w, "  %s\n", strings.TrimPrefix(f.Name, "Enable"))
		}
	}
	tplPaths := templateDirs
	if len(tplPaths) == 0 {
		tplPaths = discoverTemplatePaths()
	}
	if len(tplPaths) > 0 {
		fmt.Fprintf(w, "\nTemplates: %v\n", tplPaths)
	}
	if loginURL != "" {
		fmt.Fprintf(w, "\nLogin: %s (user: %s)\n", loginURL, loginUser)
	}
	fmt.Fprintln(w, "\n=== No traffic sent ===")
}

// adjudicateFindings runs a fail-open Haruspex triage pass over already-produced
// findings. It records, per finding, the model's "real reportable finding" probability
// in Metadata["haruspex_real_prob"], and tags unverified low-probability ones
// Metadata["haruspex_triage"]="review" so a consumer can deprioritize noise. It never
// removes, reorders, or re-severities a finding — a missed finding is the cardinal harm,
// so the model can only annotate here, never gate. Engine off / unreachable / any error
// leaves every finding exactly as emitted.
func adjudicateFindings(ctx context.Context, findings core.Findings) {
	cfg := decision.FromEnv()
	if !cfg.Enabled || len(findings) == 0 {
		return
	}
	items := make([]decision.Item, len(findings))
	for i, f := range findings {
		ev := f.Evidence
		if len(ev) > 800 {
			ev = ev[:800]
		}
		verified := ""
		if f.Verified {
			verified = " [verified]"
		}
		items[i] = decision.Item{
			Key:  f.ID,
			Text: fmt.Sprintf("%s on %s param %q%s: %s", f.Type, f.URL, f.Parameter, verified, ev),
		}
	}
	probs, err := decision.Adjudicate(ctx, cfg, items)
	if err != nil || probs == nil || len(probs) != len(findings) {
		return // fail-open: keep every finding untouched
	}
	for i, f := range findings {
		p := probs[i]
		if p == nil {
			// The engine had no opinion for this one item (e.g. an oversized
			// state it rejected) — leave the finding exactly as it was, never
			// read this as a confident "not a finding".
			continue
		}
		if f.Metadata == nil {
			f.Metadata = map[string]interface{}{}
		}
		f.Metadata["haruspex_real_prob"] = *p
		if *p < 0.5 && !f.Verified {
			f.Metadata["haruspex_triage"] = "review"
		}
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	if err := applyConfigFile(cmd); err != nil {
		return err
	}

	targets, err := collectTargets(args)
	if err != nil {
		return err
	}

	for _, target := range targets {
		parsedURL, err := url.Parse(target)
		if err != nil || parsedURL.Host == "" {
			return fmt.Errorf("invalid target URL: %s (must include scheme, e.g. https://example.com)", target)
		}
		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return fmt.Errorf("unsupported URL scheme %q: only http and https are supported", parsedURL.Scheme)
		}
	}

	// Smart auto-configuration: probe the target and auto-enable features.
	// Runs BEFORE validation so profile-derived level/risk are set first.
	autoConfig(cmd, targets)

	if level < 1 || level > 5 {
		return fmt.Errorf("level must be between 1 and 5, got %d", level)
	}
	if risk < 1 || risk > 3 {
		return fmt.Errorf("risk must be between 1 and 3, got %d", risk)
	}

	headerMap := make(map[string]string)
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("malformed header %q: must be in 'Key: Value' format", h)
		}
		headerMap[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	s := scanner.New()
	defer s.Close()

	// CLI flag wins over env; missing flag falls back to ASSAY_LOGIN_PASS.
	if loginPass == "" {
		if env := os.Getenv("ASSAY_LOGIN_PASS"); env != "" {
			loginPass = env
		}
	}

	sessionCookies := cookies
	if loginURL != "" {
		loginCtx, loginCancel := context.WithTimeout(context.Background(), 60*time.Second)
		got, lerr := performLogin(loginCtx)
		loginCancel()
		if lerr != nil {
			return fmt.Errorf("login failed: %w", lerr)
		}
		sessionCookies = mergeCookies(cookies, got)
		if verbose {
			fmt.Fprintln(os.Stderr, "[*] Authenticated: scanning with captured session")
		}
	}

	// When a proxy is set but --insecure was not explicitly passed, auto-enable
	// TLS skip. The proxy (typically Burp) terminates TLS with its own CA, so
	// direct requests fail with x509 verification errors unless skipped.
	if proxy != "" && !insecure {
		insecure = true
		if verbose {
			fmt.Fprintf(os.Stderr, "[*] --proxy set: auto-enabling --insecure (TLS verification skipped)\n")
		}
	}

	config := &scanner.Config{
		Timeout:        timeout,
		Concurrency:    concurrency,
		Verbose:        verbose,
		Headers:        headerMap,
		Cookies:        sessionCookies,
		UserAgent:      userAgent,
		Data:           data,
		Method:         method,
		ProxyURL:       proxy,
		Insecure:       insecure,
		OutputDir:      output,
		CheckpointPath: checkpointPath,
		ResumePath:     resumePath,
	}
	s.SetConfig(config)

	internalConfig := scanner.DefaultInternalConfig()
	if profile != "" {
		p := scanner.GetProfile(profile)
		internalConfig = p.Config
	}
	if err := applyCLIFlags(internalConfig); err != nil {
		return err
	}
	// Scope is ON by default: restrict traffic to the target host(s) so a scan
	// never wanders off-target, and skip session-destroying paths. Operators
	// broaden with --scope-host / --include-path, or disable with --no-scope.
	// Cross-host detectors (cloud, subdomain-takeover, external APIs) and OOB
	// callbacks use a separate unscoped client, so this does not block them.
	if !noScope {
		hosts := scopeHosts
		if len(hosts) == 0 {
			seen := map[string]bool{}
			for _, t := range targets {
				if u, e := url.Parse(t); e == nil && u.Hostname() != "" && !seen[u.Hostname()] {
					seen[u.Hostname()] = true
					hosts = append(hosts, u.Hostname())
				}
			}
		}
		sc, serr := scope.New(hosts, includePaths, excludePaths, !noDefaultExcludes)
		if serr != nil {
			return fmt.Errorf("invalid scope: %w", serr)
		}
		internalConfig.Scope = sc
		if verbose {
			fmt.Fprintf(os.Stderr, "[*] Scope: hosts=%v include=%v exclude=%v default-excludes=%v (--no-scope to disable)\n",
				hosts, includePaths, excludePaths, !noDefaultExcludes)
		}
	} else if verbose {
		fmt.Fprintln(os.Stderr, "[*] Scope disabled (--no-scope): all hosts allowed")
	}
	if ratePerSec > 0 {
		internalConfig.RateLimitPerSec = ratePerSec
		if verbose {
			fmt.Fprintf(os.Stderr, "[*] Rate limit: %.2f req/s\n", ratePerSec)
		}
	}
	// When a login was performed, keep that session alive for the scan: poll a
	// canary (an authenticated-only URL, default the first target) and re-run the
	// login on logout. --login-success is the authenticated marker.
	if loginURL != "" {
		canary := sessionCheckURL
		if canary == "" && len(targets) > 0 {
			canary = targets[0]
		}
		internalConfig.Session = session.New(sessionCookies, performLogin, canary, loginSuccess)
		internalConfig.SessionCheckInterval = sessionCheckInterval
		if verbose {
			fmt.Fprintf(os.Stderr, "[*] Session keepalive: canary=%s marker=%q every %s\n",
				canary, loginSuccess, sessionCheckInterval)
		}
	}
	if verbose && internalConfig.EnableJSDep {
		if internalConfig.NVDAPIKey != "" {
			fmt.Fprintln(os.Stderr, "[*] NVD: authenticated tier (~50 req/30s)")
		} else {
			fmt.Fprintln(os.Stderr, "[*] NVD: anonymous tier (~5 req/30s; pass --nvd-api-key or set NVD_API_KEY for higher limit)")
		}
	}
	internalConfig.Verbose = verbose

	if dryRun {
		printDryRun(targets, internalConfig)
		return nil
	}

	if err := s.SetInternalConfig(internalConfig); err != nil && verbose {
		fmt.Fprintf(os.Stderr, "Warning: Failed to configure internal scanner: %v\n", err)
	}

	for _, target := range targets {
		if err := s.AddTarget(target); err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
	}

	if !internalOnly {
		registerTools(s)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigChan:
			fmt.Fprintln(os.Stderr, "\nReceived interrupt, stopping scan...")
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(sigChan)
	}()

	formats, err := resolveFormats(formatList, jsonOutput, htmlOutput)
	if err != nil {
		return err
	}
	if verr := validateOutput(formats, outputDir); verr != nil {
		return verr
	}

	// Print the human banner only when emitting the default text report to stdout.
	if outputDir == "" && len(formats) == 1 && formats[0] == "text" {
		if len(targets) == 1 {
			printScanHeader(targets[0])
		} else {
			printScanHeader(fmt.Sprintf("%d targets", len(targets)))
		}
	}

	result, err := s.Scan(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if verifyFindings {
		runVerification(ctx, result.Findings, headerMap, sessionCookies)
	}

	// Haruspex adjudication: a FAIL-OPEN triage pass that annotates each finding with a
	// "real finding" probability (and flags likely noise for review) AFTER verification.
	// It only annotates — it never drops or reorders a finding, so it cannot cause a
	// missed finding. No engine configured / unreachable -> findings untouched.
	adjudicateFindings(ctx, result.Findings)

	// FP feedback: downgrade findings that match past false positives.
	if fpDatabasePath != "" {
		fpDB := scanner.LoadFPFeedback(fpDatabasePath)
		suppressed := fpDB.ApplyToFindings(result.Findings)
		if verbose && suppressed > 0 {
			fmt.Fprintf(os.Stderr, "[*] FP feedback: suppressed %d known false positives from %s\n",
				suppressed, fpDatabasePath)
		}
	}

	// Confidence threshold: filter out low-confidence findings for enterprise.
	if minConfidence != "" {
		before := len(result.Findings)
		result.Findings = filterByConfidence(result.Findings, minConfidence)
		if verbose && before != len(result.Findings) {
			fmt.Fprintf(os.Stderr, "[*] Confidence filter (>=%s): %d → %d findings\n",
				minConfidence, before, len(result.Findings))
		}
	}

	// Coverage summary: show what was tested and what was skipped so the
	// result is never silently incomplete.
	printCoverageSummary(result, internalConfig)

	// Write detailed coverage data if requested.
	if coveragePath != "" {
		if ct := s.CoverageData(); ct != nil {
			if err := ct.WriteJSON(coveragePath); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Coverage write failed: %v\n", err)
			} else if verbose {
				sum := ct.Summary()
				fmt.Fprintf(os.Stderr, "[*] Coverage data: %d params × %d detectors → %s\n",
					sum.UniqueParams, len(sum.DetectorsUsed), coveragePath)
			}
		}
	}

	report := reporting.NewReport(result)
	if err := writeReports(report, formats, outputDir); err != nil {
		return err
	}

	if complianceSpec != "" {
		if err := runCompliance(result.Findings, complianceSpec, outputDir); err != nil {
			return err
		}
	}

	if err := runExport(ctx, result.Findings); err != nil {
		return err
	}

	gateFindings := result.Findings
	if baselinePath != "" {
		baseline, berr := reporting.LoadBaselineFindings(baselinePath)
		if berr != nil {
			return berr
		}
		delta := reporting.DiffFindings(baseline, result.Findings)
		printDelta(delta)
		if failOnNew {
			gateFindings = delta.New
		}
	}

	fail, count, gerr := evaluateGate(gateFindings, failOn)
	if gerr != nil {
		return gerr
	}
	if fail {
		threshold, _ := core.ParseSeverity(failOn)
		return &gateError{Threshold: threshold, Count: count}
	}
	return nil
}
