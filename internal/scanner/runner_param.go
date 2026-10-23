package scanner

import (
	"context"
	"sync"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/http"
	"github.com/TyrusRC/assay/internal/iast"
)

// runParameterTests launches goroutines for all parameter-level injection
// tests, bounded by a semaphore so a target with many parameters doesn't
// flood the server with hundreds of concurrent requests. Each parameter is
// reported to prog as tested once its detectors finish.
//
// tierFilter, when non-nil, restricts which detector classes run. Pass
// nil to run all applicable detectors (full tier). This enables tiered
// testing: body params get all detectors, headers get only sqli+cmdi.
func (s *InternalScanner) runParameterTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, params []core.Parameter, targetURL, method string, scanClient *http.Client, prog *Progress, tierFilter map[string]bool) {
	concurrency := s.config.ParamConcurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	sem := make(chan struct{}, concurrency)

	// Group body params by endpoint so each param's client includes its
	// siblings. Without this, SendPayloadInJSON sends {"username":"PAYLOAD"}
	// alone and the server returns 400 "missing password" before the SQL runs.
	type epKey struct{ url, method string }
	epParams := make(map[epKey][]core.Parameter)
	for _, p := range params {
		u := targetURL
		m := method
		if p.SourceURL != "" {
			u = p.SourceURL
		}
		if p.Method != "" {
			m = p.Method
		}
		k := epKey{u, m}
		epParams[k] = append(epParams[k], p)
	}

	for _, param := range params {
		wg.Add(1)
		go func(p core.Parameter) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			injURL := targetURL
			injMethod := method
			if p.SourceURL != "" {
				injURL = p.SourceURL
			}
			if p.Method != "" {
				injMethod = p.Method
			}
			siblings := epParams[epKey{injURL, injMethod}]
			s.runParamDetectors(ctx, findingsChan, injURL, p, injMethod, scanClient, siblings, tierFilter)
			if prog != nil {
				prog.IncrementTested()
			}
		}(param)
	}
}

// paramTest represents a named, enabled detector test for a parameter.
type paramTest struct {
	name    string
	enabled bool
	run     func() []*core.Finding
}

// applicableTests returns which detectors should run based on parameter location.
// This prevents running irrelevant detectors (e.g., LFI on a cookie parameter).
func (s *InternalScanner) applicableTests(param core.Parameter) []paramTest {
	allTests := []struct {
		name    string
		enabled bool
	}{
		{"sqli", s.config.EnableSQLi},
		{"xss", s.config.EnableXSS},
		{"cmdi", s.config.EnableCMDI},
		{"ssrf", s.config.EnableSSRF},
		{"lfi", s.config.EnableLFI},
		{"xxe", s.config.EnableXXE},
		{"nosql", s.config.EnableNoSQL},
		{"ssti", s.config.EnableSSTI},
		{"redirect", s.config.EnableRedirect},
		{"crlf", s.config.EnableCRLF},
		{"ldap", s.config.EnableLDAP},
		{"xpath", s.config.EnableXPath},
		{"headerinj", s.config.EnableHeaderInj},
		{"csti", s.config.EnableCSTI},
		{"rfi", s.config.EnableRFI},
		{"csvinj", s.config.EnableCSVInj},
		{"cachepoisoning", s.config.EnableCachePoisoning},
		{"cssinj", s.config.EnableCSSInj},
		{"deser", s.config.EnableDeser},
		{"domclobber", s.config.EnableDOMClobber},
		{"emailinj", s.config.EnableEmailInj},
		{"hpp", s.config.EnableHPP},
		{"htmlinj", s.config.EnableHTMLInj},
		{"massassign", s.config.EnableMassAssign},
		{"protopollserver", s.config.EnableProtoPollServer},
		{"ssi", s.config.EnableSSI},
	}

	var applicableNames map[string]bool

	switch param.Location {
	case core.ParamLocationQuery, core.ParamLocationBody:
		applicableNames = nil // nil means all
	case core.ParamLocationCookie:
		applicableNames = map[string]bool{
			"sqli": true, "xss": true, "crlf": true,
			"headerinj": true, "nosql": true,
		}
	case core.ParamLocationHeader:
		applicableNames = map[string]bool{
			"sqli": true, "crlf": true, "headerinj": true, "ssti": true,
			"ssrf": true, "nosql": true, "cmdi": true, "lfi": true,
		}
	case core.ParamLocationPath:
		applicableNames = map[string]bool{
			"sqli": true, "lfi": true, "cmdi": true, "nosql": true, "xpath": true,
		}
	case core.ParamLocationLocalStorage, core.ParamLocationSessionStorage:
		applicableNames = map[string]bool{
			"xss": true,
		}
	default:
		applicableNames = nil
	}

	var result []paramTest
	for _, t := range allTests {
		if !t.enabled {
			continue
		}
		if applicableNames != nil && !applicableNames[t.name] {
			continue
		}
		result = append(result, paramTest{
			name:    t.name,
			enabled: t.enabled,
		})
	}
	return result
}

// runParamDetectors runs location-appropriate detectors for a single parameter.
//
// A per-param client (ForParam) ensures every detector's SendPayload call
// routes through SendPayloadAt, injecting the payload at the correct
// location (JSON body, path segment, header, XML, cookie, query) without
// any detector code changes.
func (s *InternalScanner) runParamDetectors(ctx context.Context, findingsChan chan<- *core.Finding, targetURL string, param core.Parameter, method string, scanClient *http.Client, siblings []core.Parameter, tierFilter map[string]bool) {
	pc := scanClient.ForParam(param).WithSiblings(siblings)

	runners := map[string]func() []*core.Finding{
		"sqli":            func() []*core.Finding { return s.testSQLiWithClient(ctx, targetURL, param, method, pc) },
		"xss":             func() []*core.Finding { return s.testXSSWithClient(ctx, targetURL, param, method, pc) },
		"cmdi":            func() []*core.Finding { return s.testCMDIWithClient(ctx, targetURL, param, method, pc) },
		"ssrf":            func() []*core.Finding { return s.testSSRFWithClient(ctx, targetURL, param, method, pc) },
		"lfi":             func() []*core.Finding { return s.testLFIWithClient(ctx, targetURL, param, method, pc) },
		"xxe":             func() []*core.Finding { return s.testXXEWithClient(ctx, targetURL, param, method, pc) },
		"nosql":           func() []*core.Finding { return s.testNoSQLWithClient(ctx, targetURL, param, method, pc) },
		"ssti":            func() []*core.Finding { return s.testSSTIWithClient(ctx, targetURL, param, method, pc) },
		"redirect":        func() []*core.Finding { return s.testRedirectWithClient(ctx, targetURL, param, method, pc) },
		"crlf":            func() []*core.Finding { return s.testCRLFWithClient(ctx, targetURL, param, method, pc) },
		"ldap":            func() []*core.Finding { return s.testLDAPWithClient(ctx, targetURL, param, method, pc) },
		"xpath":           func() []*core.Finding { return s.testXPathWithClient(ctx, targetURL, param, method, pc) },
		"headerinj":       func() []*core.Finding { return s.testHeaderInjWithClient(ctx, targetURL, param, method, pc) },
		"csti":            func() []*core.Finding { return s.testCSTIWithClient(ctx, targetURL, param, method, pc) },
		"rfi":             func() []*core.Finding { return s.testRFIWithClient(ctx, targetURL, param, method, pc) },
		"csvinj":          func() []*core.Finding { return s.testCSVInjWithClient(ctx, targetURL, param, method, pc) },
		"cachepoisoning":  func() []*core.Finding { return s.testCachePoisoningWithClient(ctx, targetURL, param, method, pc) },
		"cssinj":          func() []*core.Finding { return s.testCSSInjWithClient(ctx, targetURL, param, method, pc) },
		"deser":           func() []*core.Finding { return s.testDeserWithClient(ctx, targetURL, param, method, pc) },
		"domclobber":      func() []*core.Finding { return s.testDOMClobberWithClient(ctx, targetURL, param, method, pc) },
		"emailinj":        func() []*core.Finding { return s.testEmailInjWithClient(ctx, targetURL, param, method, pc) },
		"hpp":             func() []*core.Finding { return s.testHPPWithClient(ctx, targetURL, param, method, pc) },
		"htmlinj":         func() []*core.Finding { return s.testHTMLInjWithClient(ctx, targetURL, param, method, pc) },
		"massassign":      func() []*core.Finding { return s.testMassAssignWithClient(ctx, targetURL, param, method, pc) },
		"protopollserver": func() []*core.Finding { return s.testProtoPollServerWithClient(ctx, targetURL, param, method, pc) },
		"ssi":             func() []*core.Finding { return s.testSSIWithClient(ctx, targetURL, param, method, pc) },
	}

	applicable := s.applicableTests(param)

	// Tier filter: restrict detectors per param tier (body=all, query=top5, header=sqli+cmdi).
	if tierFilter != nil {
		var filtered []paramTest
		for _, t := range applicable {
			if tierFilter[t.name] {
				filtered = append(filtered, t)
			}
		}
		applicable = filtered
	}

	// --test filter: run only named detector classes.
	if len(s.config.OnlyTests) > 0 {
		allowed := make(map[string]bool, len(s.config.OnlyTests))
		for _, t := range s.config.OnlyTests {
			allowed[t] = true
		}
		var filtered []paramTest
		for _, t := range applicable {
			if allowed[t.name] {
				filtered = append(filtered, t)
			}
		}
		applicable = filtered
	}

	// Run detector classes in parallel within each param. Default 3
	// concurrent detector goroutines per param keeps request volume
	// bounded while cutting wall-clock time ~3x on multi-class params.
	detConc := s.config.DetectorConcurrency
	if detConc <= 0 {
		detConc = 3
	}
	detSem := make(chan struct{}, detConc)
	var detWg sync.WaitGroup

	for _, t := range applicable {
		if s.confirmed.shouldSkip(param.Name, t.name) {
			if s.coverageTracker != nil {
				s.coverageTracker.Record(CoverageRecord{
					URL: targetURL, Parameter: param.Name,
					Location: param.Location, Detector: t.name, Status: "skipped",
				})
			}
			continue
		}
		runner, ok := runners[t.name]
		if !ok {
			continue
		}
		detWg.Add(1)
		detSem <- struct{}{}
		go func(name string, run func() []*core.Finding) {
			defer detWg.Done()
			defer func() { <-detSem }()
			start := time.Now()
			findings := run()
			elapsed := time.Since(start)
			status := "tested"
			if ctx.Err() != nil {
				status = "timeout"
			}
			if s.coverageTracker != nil {
				s.coverageTracker.Record(CoverageRecord{
					URL:       targetURL,
					Parameter: param.Name,
					Location:  param.Location,
					Detector:  name,
					Status:    status,
					Findings:  len(findings),
					Duration:  elapsed,
				})
			}
			if len(findings) > 0 {
				s.confirmed.confirm(param.Name, name)
				emit(ctx, findingsChan, findings)
				s.recordInjectionCandidate(targetURL, param, method, name, findings[0])
			}
		}(t.name, runner)
	}
	detWg.Wait()

	// IAST taint probe: if the callback server is running, send one
	// marker-wrapped payload per high-value sink type. If the sensor
	// reports the marker reached the sink, record a confirmed candidate.
	if s.iastServer != nil && param.Location == core.ParamLocationBody {
		s.probeIASTSinks(ctx, targetURL, param, method, pc)
	}
}

// probeIASTSinks sends taint-marker payloads for the 4 highest-value
// sink types and waits briefly for the deployed sensor to call back.
func (s *InternalScanner) probeIASTSinks(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) {
	sinkTypes := []struct {
		sink    string
		payload string
	}{
		{iast.SinkSQLQuery, "' OR '1'='1"},
		{iast.SinkSysCommand, ";id"},
		{iast.SinkFileOpen, "../../../../etc/passwd"},
		{iast.SinkUnserialize, "O:8:\"stdClass\":0:{}"},
	}

	for _, st := range sinkTypes {
		select {
		case <-ctx.Done():
			return
		default:
		}
		markerID, _ := iast.GenerateMarker(st.sink)
		fullPayload := iast.WrapPayload(st.payload, markerID, st.sink)
		_, _ = pc.SendPayload(ctx, targetURL, param.Name, fullPayload, method)

		hit := s.iastServer.WaitForHit(markerID, 2*time.Second)
		if hit != nil {
			s.recordInjectionCandidate(targetURL, param, method, st.sink, &core.Finding{
				Evidence:    "IAST: taint marker reached " + hit.SinkType + " sink",
				Description: "IAST sensor confirmed payload reached " + hit.SinkType + " sink. Stack: " + hit.StackTrace,
				Confidence:  core.ConfidenceConfirmed,
			})
		}
	}
}
