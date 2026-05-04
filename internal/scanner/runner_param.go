package scanner

import (
	"context"
	"sync"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/core"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/http"
)

// runParameterTests launches goroutines for all parameter-level injection tests.
func (s *InternalScanner) runParameterTests(ctx context.Context, wg *sync.WaitGroup, findingsChan chan<- *core.Finding, params []core.Parameter, targetURL, method string, scanClient *http.Client) {
	for _, param := range params {
		wg.Add(1)
		go func(p core.Parameter) {
			defer wg.Done()
			s.runParamDetectors(ctx, findingsChan, targetURL, p, method, scanClient)
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
			"crlf": true, "headerinj": true, "ssti": true, "ssrf": true,
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
func (s *InternalScanner) runParamDetectors(ctx context.Context, findingsChan chan<- *core.Finding, targetURL string, param core.Parameter, method string, scanClient *http.Client) {
	runners := map[string]func() []*core.Finding{
		"sqli":            func() []*core.Finding { return s.testSQLiWithClient(ctx, targetURL, param, method, scanClient) },
		"xss":             func() []*core.Finding { return s.testXSS(ctx, targetURL, param, method) },
		"cmdi":            func() []*core.Finding { return s.testCMDI(ctx, targetURL, param, method) },
		"ssrf":            func() []*core.Finding { return s.testSSRF(ctx, targetURL, param, method) },
		"lfi":             func() []*core.Finding { return s.testLFI(ctx, targetURL, param, method) },
		"xxe":             func() []*core.Finding { return s.testXXEInParam(ctx, targetURL, param, method) },
		"nosql":           func() []*core.Finding { return s.testNoSQL(ctx, targetURL, param, method) },
		"ssti":            func() []*core.Finding { return s.testSSTI(ctx, targetURL, param, method) },
		"redirect":        func() []*core.Finding { return s.testRedirect(ctx, targetURL, param, method) },
		"crlf":            func() []*core.Finding { return s.testCRLF(ctx, targetURL, param, method) },
		"ldap":            func() []*core.Finding { return s.testLDAP(ctx, targetURL, param, method) },
		"xpath":           func() []*core.Finding { return s.testXPath(ctx, targetURL, param, method) },
		"headerinj":       func() []*core.Finding { return s.testHeaderInj(ctx, targetURL, param, method) },
		"csti":            func() []*core.Finding { return s.testCSTI(ctx, targetURL, param, method) },
		"rfi":             func() []*core.Finding { return s.testRFI(ctx, targetURL, param, method) },
		"csvinj":          func() []*core.Finding { return s.testCSVInj(ctx, targetURL, param, method) },
		"cachepoisoning":  func() []*core.Finding { return s.testCachePoisoning(ctx, targetURL, param, method) },
		"cssinj":          func() []*core.Finding { return s.testCSSInj(ctx, targetURL, param, method) },
		"deser":           func() []*core.Finding { return s.testDeser(ctx, targetURL, param, method) },
		"domclobber":      func() []*core.Finding { return s.testDOMClobber(ctx, targetURL, param, method) },
		"emailinj":        func() []*core.Finding { return s.testEmailInj(ctx, targetURL, param, method) },
		"hpp":             func() []*core.Finding { return s.testHPP(ctx, targetURL, param, method) },
		"htmlinj":         func() []*core.Finding { return s.testHTMLInj(ctx, targetURL, param, method) },
		"massassign":      func() []*core.Finding { return s.testMassAssign(ctx, targetURL, param, method) },
		"protopollserver": func() []*core.Finding { return s.testProtoPollServer(ctx, targetURL, param, method) },
		"ssi":             func() []*core.Finding { return s.testSSI(ctx, targetURL, param, method) },
	}

	applicable := s.applicableTests(param)
	for _, t := range applicable {
		if s.confirmed.shouldSkip(param.Name, t.name) {
			continue
		}
		runner, ok := runners[t.name]
		if !ok {
			continue
		}
		findings := runner()
		if len(findings) > 0 {
			s.confirmed.confirm(param.Name, t.name)
			emit(ctx, findingsChan, findings)
		}
	}
}
