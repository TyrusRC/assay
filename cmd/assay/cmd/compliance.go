package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TyrusRC/assay/internal/compliance"
	"github.com/TyrusRC/assay/internal/core"
)

// resolveFrameworks turns the --compliance spec (comma-separated names or
// "all") into the set of frameworks to assess.
func resolveFrameworks(spec string) ([]compliance.Framework, error) {
	if strings.EqualFold(strings.TrimSpace(spec), "all") {
		return compliance.Frameworks(), nil
	}
	parts := strings.Split(spec, ",")
	out := make([]compliance.Framework, 0, len(parts))
	for _, name := range parts {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		fw, err := compliance.ParseFramework(name)
		if err != nil {
			return nil, err
		}
		out = append(out, fw)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no compliance frameworks specified")
	}
	return out, nil
}

// runCompliance writes a Markdown compliance assessment per requested framework:
// to outputDir/compliance-<fw>.md when an output dir is set, otherwise to
// stdout.
func runCompliance(findings core.Findings, spec, outputDir string) error {
	frameworks, err := resolveFrameworks(spec)
	if err != nil {
		return err
	}
	for _, fw := range frameworks {
		assessment := compliance.Assess(findings, fw)
		if outputDir == "" {
			if err := assessment.WriteMarkdown(os.Stdout); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(outputDir, 0o755); err != nil {
			return fmt.Errorf("create output dir: %w", err)
		}
		path := filepath.Join(outputDir, "compliance-"+string(fw)+".md")
		file, cerr := os.Create(path)
		if cerr != nil {
			return fmt.Errorf("create %s: %w", path, cerr)
		}
		werr := assessment.WriteMarkdown(file)
		file.Close()
		if werr != nil {
			return fmt.Errorf("write %s: %w", path, werr)
		}
		fmt.Fprintf(os.Stderr, "[+] wrote %s\n", path)
	}
	return nil
}
