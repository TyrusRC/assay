package scanner

import (
	"context"
	"fmt"
	"os"

	"github.com/TyrusRC/assay/internal/core"
	"github.com/TyrusRC/assay/internal/payloads/arginject"
	"github.com/TyrusRC/assay/internal/payloads/esi"
	"github.com/TyrusRC/assay/internal/payloads/fileops"
	"github.com/TyrusRC/assay/internal/payloads/javareflect"
	"github.com/TyrusRC/assay/internal/payloads/nodejsinject"
	"github.com/TyrusRC/assay/internal/payloads/phpinject"
	"github.com/TyrusRC/assay/internal/payloads/solrinject"
)

// This file groups the bank-driven parameter-injection detectors added
// in the AWVS-gap-closure series. Each runs the same shape: baseline
// fetch, per-param payload injection, marker-pattern match against the
// payload bank's GetErrorPatterns / engine fingerprints.

// capPayloads honours s.config.MaxPayloadsPerParam when it is set lower
// than the per-detector default. Centralising the comparison keeps each
// testXxx wrapper terse.
func (s *InternalScanner) capPayloads(detectorDefault int) int {
	if s.config.MaxPayloadsPerParam > 0 && s.config.MaxPayloadsPerParam < detectorDefault {
		return s.config.MaxPayloadsPerParam
	}
	return detectorDefault
}

// testESI probes URL parameters for Edge Side Includes injection by
// injecting fingerprint ESI payloads and looking for engine-evaluation
// markers in the response.
func (s *InternalScanner) testESI(ctx context.Context, targetURL string) []*core.Finding {
	if s.esiDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing ESI injection on '%s'...\n", targetURL)
	}
	opts := esi.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	opts.MaxPayloadsPerParam = s.capPayloads(opts.MaxPayloadsPerParam)
	opts.BaselineCache = s.baselineCache
	res, err := s.esiDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testSolrInject probes URL parameters for Apache Solr injection.
// Gated on baseline showing Solr error patterns when
// ConfirmedSolrOnly is enabled — keeps RCE payloads off non-Solr targets.
func (s *InternalScanner) testSolrInject(ctx context.Context, targetURL string) []*core.Finding {
	if s.solrInjectDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing Apache Solr injection on '%s'...\n", targetURL)
	}
	opts := solrinject.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	opts.MaxPayloadsPerParam = s.capPayloads(opts.MaxPayloadsPerParam)
	opts.BaselineCache = s.baselineCache
	res, err := s.solrInjectDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testPHPInject probes URL parameters for PHP user-controlled sinks
// (extract / assert / preg_replace /e / include / unserialize / dynamic
// instantiation). RCE-class payloads self-gate on a PHP fingerprint.
func (s *InternalScanner) testPHPInject(ctx context.Context, targetURL string) []*core.Finding {
	if s.phpInjectDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing PHP user-controlled sinks on '%s'...\n", targetURL)
	}
	opts := phpinject.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	opts.MaxPayloadsPerParam = s.capPayloads(opts.MaxPayloadsPerParam)
	opts.BaselineCache = s.baselineCache
	res, err := s.phpInjectDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testJavaReflect probes URL parameters for Java reflection abuse
// (Runtime.exec via reflection, ProcessBuilder, classLoader chains,
// JNDI lookups). RCE-class payloads self-gate on a Java fingerprint.
func (s *InternalScanner) testJavaReflect(ctx context.Context, targetURL string) []*core.Finding {
	if s.javaReflectDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing Java reflection abuse on '%s'...\n", targetURL)
	}
	opts := javareflect.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	opts.MaxPayloadsPerParam = s.capPayloads(opts.MaxPayloadsPerParam)
	opts.BaselineCache = s.baselineCache
	res, err := s.javaReflectDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testNodeJSInject probes URL parameters for Server-Side JavaScript
// Injection. Supports time-blind sleep detection alongside error-pattern
// matching. RCE-class payloads self-gate on a Node fingerprint.
func (s *InternalScanner) testNodeJSInject(ctx context.Context, targetURL string) []*core.Finding {
	if s.nodejsInjectDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing NodeJS SSJI on '%s'...\n", targetURL)
	}
	opts := nodejsinject.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	opts.MaxPayloadsPerParam = s.capPayloads(opts.MaxPayloadsPerParam)
	res, err := s.nodejsInjectDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testArgInject probes URL parameters for argument injection into
// wrapped binaries (curl/git/ssh/tar/find/convert/python/php/ruby/perl/…).
// Matches per-binary error patterns that confirm the flag landed in argv.
func (s *InternalScanner) testArgInject(ctx context.Context, targetURL string) []*core.Finding {
	if s.argInjectDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing argument injection on '%s'...\n", targetURL)
	}
	opts := arginject.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	opts.MaxPayloadsPerParam = s.capPayloads(opts.MaxPayloadsPerParam)
	opts.BaselineCache = s.baselineCache
	res, err := s.argInjectDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}

// testFileOps probes URL parameters for arbitrary file create / delete /
// tamper sinks via path traversal. Matches filesystem error patterns
// (Permission denied, ENOENT, fopen failed, …) referencing the
// traversed path.
func (s *InternalScanner) testFileOps(ctx context.Context, targetURL string) []*core.Finding {
	if s.fileOpsDetector == nil {
		return nil
	}
	if s.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Testing arbitrary file-ops on '%s'...\n", targetURL)
	}
	opts := fileops.DefaultOptions()
	opts.Timeout = s.config.RequestTimeout
	opts.MaxPayloadsPerParam = s.capPayloads(opts.MaxPayloadsPerParam)
	opts.BaselineCache = s.baselineCache
	res, err := s.fileOpsDetector.Detect(ctx, targetURL, opts)
	if err != nil || res == nil || !res.Vulnerable {
		return nil
	}
	return res.Findings
}
