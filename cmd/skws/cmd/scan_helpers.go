package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/scanner"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/tools/nuclei"
	"github.com/TyrusRC/swiss-knife-for-web-security/internal/tools/sqlmap"
)

// collectTargets gathers target URLs from CLI args, a file, or stdin.
func collectTargets(args []string) ([]string, error) {
	if targetList != "" {
		f, err := os.Open(targetList)
		if err != nil {
			return nil, fmt.Errorf("cannot open target list file: %w", err)
		}
		defer f.Close()
		targets := readTargetsFromReader(f)
		if len(targets) == 0 {
			return nil, fmt.Errorf("no valid targets found in %s", targetList)
		}
		return targets, nil
	}

	if len(args) > 0 {
		return []string{args[0]}, nil
	}

	stat, err := os.Stdin.Stat()
	if err == nil && stat.Mode()&os.ModeCharDevice == 0 {
		targets := readTargetsFromReader(os.Stdin)
		if len(targets) > 0 {
			return targets, nil
		}
	}

	return nil, fmt.Errorf("no targets provided: specify a URL argument, use --list, or pipe URLs via stdin")
}

// readTargetsFromReader reads URLs from an io.Reader, one per line.
// Empty lines and lines starting with '#' are skipped.
func readTargetsFromReader(r *os.File) []string {
	var targets []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	return targets
}

// registerTools wires the external tool wrappers (SQLMap, Nuclei) onto
// the scanner. Tools whose binaries are not on PATH register but
// gracefully no-op at scan time.
func registerTools(s *scanner.Scanner) {
	sqlmapTool := sqlmap.New().WithOptions(sqlmap.Options{
		Level:   level,
		Risk:    risk,
		Threads: concurrency,
	})
	s.RegisterTool(sqlmapTool)

	if !noNuclei {
		nucleiTool := nuclei.New()
		if nucleiTool.IsAvailable() {
			opts := nucleiTool.DefaultOptions()
			if templateDir != "" {
				opts.TemplatePaths = []string{templateDir}
			}
			if nucleiTags != "" {
				opts.Tags = splitCSV(nucleiTags)
			}
			if nucleiSev != "" {
				opts.Severity = splitCSV(nucleiSev)
			}
			nucleiTool.WithOptions(opts)
			s.RegisterTool(nucleiTool)
		}
	}

	// TODO: Add more tools as they are implemented
	// - ffuf
	// - nikto
}

// parseHeaderArray parses repeated 'Key: Value' header flags into a map.
// Used by --auth-a-header / --auth-b-header to build the per-identity
// header set for the two-identity IDOR probe. Empty input returns a
// non-nil empty map so callers can safely range over it.
func parseHeaderArray(raw []string) (map[string]string, error) {
	out := make(map[string]string, len(raw))
	for _, h := range raw {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed header %q: must be in 'Key: Value' format", h)
		}
		out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return out, nil
}

// splitCSV splits a comma-separated string into a trimmed, non-empty slice.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func printScanHeader(target string) {
	fmt.Println("╔════════════════════════════════════════════════════════╗")
	fmt.Println("║    SKWS - Swiss Knife for Web Security Scanner        ║")
	fmt.Println("╚════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Started: %s\n", time.Now().Format(time.RFC3339))
	fmt.Println()
	fmt.Println("Scanning...")
	fmt.Println()
}
