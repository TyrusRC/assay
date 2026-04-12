package executor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/swiss-knife-for-web-security/skws/internal/templates"
	"github.com/swiss-knife-for-web-security/skws/internal/templates/matchers"
)

const (
	// defaultMaxFileSize is 10 MB.
	defaultMaxFileSize int64 = 10 * 1024 * 1024
)

// FileExecutor executes file-based template probes against local file paths.
type FileExecutor struct {
	matcherEngine *matchers.MatcherEngine
	maxFileSize   int64
}

// NewFileExecutor creates a new file executor with a default 10 MB size limit.
func NewFileExecutor() *FileExecutor {
	return &FileExecutor{
		matcherEngine: matchers.New(),
		maxFileSize:   defaultMaxFileSize,
	}
}

// Execute walks the directory (or reads the single file) at path,
// applies extension / denylist / size filters, reads matching files,
// evaluates matchers, and returns one ExecutionResult per matched file.
func (e *FileExecutor) Execute(path string, fileMatch *templates.FileMatch) ([]*templates.ExecutionResult, error) {
	maxSize := e.maxFileSize
	if fileMatch.MaxSize != "" {
		parsed, err := parseSize(fileMatch.MaxSize)
		if err != nil {
			return nil, fmt.Errorf("file executor: parse max-size %q: %w", fileMatch.MaxSize, err)
		}
		maxSize = parsed
	}

	// Build lookup sets for fast filtering.
	allowedExts := make(map[string]struct{}, len(fileMatch.Extensions))
	for _, ext := range fileMatch.Extensions {
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		allowedExts[strings.ToLower(ext)] = struct{}{}
	}

	deniedExts := make(map[string]struct{}, len(fileMatch.DenyList))
	for _, ext := range fileMatch.DenyList {
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		deniedExts[strings.ToLower(ext)] = struct{}{}
	}

	var results []*templates.ExecutionResult

	walkErr := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			// Propagate errors on the root path so callers can detect them.
			// For sub-entries simply skip.
			if filePath == path {
				return err
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(filePath))

		// Extension allowlist filter.
		if len(allowedExts) > 0 {
			if _, ok := allowedExts[ext]; !ok {
				return nil
			}
		}

		// Denylist filter.
		if _, denied := deniedExts[ext]; denied {
			return nil
		}

		// Size filter.
		if info.Size() > maxSize {
			return nil
		}

		content, readErr := os.ReadFile(filePath)
		if readErr != nil {
			return nil // Skip unreadable files.
		}

		body := string(content)
		resp := &matchers.Response{
			Body: body,
			Raw:  body,
			URL:  filePath,
		}

		matched, extracts := e.matcherEngine.MatchAll(fileMatch.Matchers, "", resp, nil)
		if !matched {
			return nil
		}

		results = append(results, &templates.ExecutionResult{
			Matched:       true,
			URL:           filePath,
			ExtractedData: extracts,
			Response:      body,
			Request:       fmt.Sprintf("FILE %s", filePath),
			Timestamp:     time.Now(),
		})

		return nil
	})
	if walkErr != nil {
		return results, fmt.Errorf("file executor: walk %q: %w", path, walkErr)
	}

	return results, nil
}

// parseSize parses a human-readable size string such as "10KB", "5MB", "2GB"
// and returns the equivalent number of bytes.
// Supported suffixes (case-insensitive): B, KB, MB, GB, TB.
// A bare integer (no suffix) is interpreted as bytes.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}

	// Separate the numeric part from the unit suffix.
	// Walk from the end while it looks like a letter.
	i := len(s)
	for i > 0 && isLetter(s[i-1]) {
		i--
	}

	numStr := strings.TrimSpace(s[:i])
	unit := strings.ToUpper(strings.TrimSpace(s[i:]))

	if numStr == "" {
		return 0, fmt.Errorf("no numeric value in %q", s)
	}

	var value int64
	if _, err := fmt.Sscanf(numStr, "%d", &value); err != nil {
		return 0, fmt.Errorf("invalid number %q in size string", numStr)
	}

	switch unit {
	case "", "B":
		// bytes - no multiplication needed
	case "KB", "K":
		value *= 1024
	case "MB", "M":
		value *= 1024 * 1024
	case "GB", "G":
		value *= 1024 * 1024 * 1024
	case "TB", "T":
		value *= 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unknown size unit %q", unit)
	}

	return value, nil
}

// isLetter reports whether b is an ASCII letter.
func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
