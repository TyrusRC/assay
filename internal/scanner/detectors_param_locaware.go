package scanner

// Location-aware detector wrappers. Each creates a fresh detector instance
// with the per-param client (ForParam) so SendPayload dispatches through
// SendPayloadAt. This makes every detector inject at the correct location
// (JSON body, path segment, header, XML, cookie, query) without changing
// the detector's own code.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/detection/cachepoisoning"
	"github.com/TyrusRC/assay/internal/detection/cmdi"
	"github.com/TyrusRC/assay/internal/detection/crlf"
	"github.com/TyrusRC/assay/internal/detection/cssinj"
	"github.com/TyrusRC/assay/internal/detection/csti"
	"github.com/TyrusRC/assay/internal/detection/csvinj"
	"github.com/TyrusRC/assay/internal/detection/deser"
	"github.com/TyrusRC/assay/internal/detection/domclobber"
	"github.com/TyrusRC/assay/internal/detection/emailinj"
	"github.com/TyrusRC/assay/internal/detection/headerinj"
	"github.com/TyrusRC/assay/internal/detection/hpp"
	"github.com/TyrusRC/assay/internal/detection/htmlinj"
	"github.com/TyrusRC/assay/internal/detection/ldap"
	"github.com/TyrusRC/assay/internal/detection/lfi"
	"github.com/TyrusRC/assay/internal/detection/massassign"
	"github.com/TyrusRC/assay/internal/detection/nosql"
	"github.com/TyrusRC/assay/internal/detection/protopollution"
	"github.com/TyrusRC/assay/internal/detection/redirect"
	"github.com/TyrusRC/assay/internal/detection/rfi"
	"github.com/TyrusRC/assay/internal/detection/ssrf"
	"github.com/TyrusRC/assay/internal/detection/ssi"
	"github.com/TyrusRC/assay/internal/detection/ssti"
	"github.com/TyrusRC/assay/internal/detection/xpath"
	"github.com/TyrusRC/assay/internal/detection/xss"
	"github.com/TyrusRC/assay/internal/detection/xxe"
	"github.com/TyrusRC/assay/internal/http"
)

func (s *InternalScanner) testXSSWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	det := xss.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, xss.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testCMDIWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CMDI on param '%s'...\n", param.Name)
	}
	det := cmdi.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.DetectParam(ctx, targetURL, param, method, cmdi.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
		EnableTimeBased:  true,
		TimeBasedDelay:   5 * time.Second,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testSSRFWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing SSRF on param '%s'...\n", param.Name)
	}
	det := ssrf.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, ssrf.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testLFIWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing LFI on param '%s'...\n", param.Name)
	}
	det := lfi.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, lfi.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
		TestWrappers:     true,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testXXEWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing XXE on param '%s'...\n", param.Name)
	}
	det := xxe.New(pc)
	det.WithVerbose(s.config.Verbose)

	opts := xxe.DefaultOptions()
	opts.MaxPayloads = s.config.MaxPayloadsPerParam
	opts.Timeout = s.config.RequestTimeout

	if param.Location == core.ParamLocationBody && strings.Contains(strings.ToLower(param.ContentType), "xml") {
		opts.ContentType = param.ContentType
		result, err := det.DetectInXMLBody(ctx, targetURL, param.Name, method, opts)
		if err != nil || !result.Vulnerable {
			return nil
		}
		return result.Findings
	}

	result, err := det.DetectInParameter(ctx, targetURL, param.Name, method, opts)
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testNoSQLWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing NoSQL Injection on param '%s'...\n", param.Name)
	}
	det := nosql.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, nosql.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testSSTIWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing SSTI on param '%s'...\n", param.Name)
	}
	det := ssti.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, ssti.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
		TestAllEngines:   true,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testRedirectWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing Open Redirect on param '%s'...\n", param.Name)
	}
	det := redirect.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, redirect.DetectOptions{
		MaxPayloads:   s.config.MaxPayloadsPerParam,
		Timeout:       s.config.RequestTimeout,
		IncludeBypass: s.config.IncludeWAFBypass,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testCRLFWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CRLF Injection on param '%s'...\n", param.Name)
	}
	det := crlf.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, crlf.DetectOptions{
		MaxPayloads:         s.config.MaxPayloadsPerParam,
		Timeout:             s.config.RequestTimeout,
		TestHeaderInjection: true,
		TestResponseSplit:   true,
		IncludeAllEncodings: s.config.IncludeWAFBypass,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testLDAPWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing LDAP Injection on param '%s'...\n", param.Name)
	}
	det := ldap.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, ldap.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testXPathWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing XPath Injection on param '%s'...\n", param.Name)
	}
	det := xpath.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, xpath.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testHeaderInjWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing Header Injection on param '%s'...\n", param.Name)
	}
	det := headerinj.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, headerinj.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testCSTIWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CSTI on param '%s'...\n", param.Name)
	}
	det := csti.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, csti.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testRFIWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing RFI on param '%s'...\n", param.Name)
	}
	det := rfi.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, rfi.DetectOptions{
		MaxPayloads:      s.config.MaxPayloadsPerParam,
		IncludeWAFBypass: s.config.IncludeWAFBypass,
		Timeout:          s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testCSVInjWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CSV injection on param '%s'...\n", param.Name)
	}
	det := csvinj.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, csvinj.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testCachePoisoningWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing cache poisoning on param '%s'...\n", param.Name)
	}
	det := cachepoisoning.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, cachepoisoning.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testCSSInjWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing CSS injection on param '%s'...\n", param.Name)
	}
	det := cssinj.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, cssinj.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testDeserWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing deserialization on param '%s'...\n", param.Name)
	}
	det := deser.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, deser.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testDOMClobberWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing DOM clobbering on param '%s'...\n", param.Name)
	}
	det := domclobber.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, domclobber.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testEmailInjWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing email injection on param '%s'...\n", param.Name)
	}
	det := emailinj.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, emailinj.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testHPPWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing HPP on param '%s'...\n", param.Name)
	}
	det := hpp.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, hpp.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testHTMLInjWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing HTML injection on param '%s'...\n", param.Name)
	}
	det := htmlinj.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, htmlinj.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testMassAssignWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing mass assignment on param '%s'...\n", param.Name)
	}
	det := massassign.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, massassign.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testProtoPollServerWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing prototype pollution (server) on param '%s'...\n", param.Name)
	}
	det := protopollution.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, protopollution.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}

func (s *InternalScanner) testSSIWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, pc *http.Client) []*core.Finding {
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing SSI on param '%s'...\n", param.Name)
	}
	det := ssi.New(pc)
	det.WithVerbose(s.config.Verbose)
	result, err := det.Detect(ctx, targetURL, param.Name, method, ssi.DetectOptions{
		MaxPayloads: s.config.MaxPayloadsPerParam,
		Timeout:     s.config.RequestTimeout,
	})
	if err != nil || !result.Vulnerable {
		return nil
	}
	return result.Findings
}
