package smuggling

import (
	"errors"
	"time"
)

// SmugglingType represents the type of HTTP request smuggling vulnerability.
type SmugglingType int

const (
	// TypeUnknown indicates an unknown or unclassified smuggling type.
	TypeUnknown SmugglingType = iota
	// TypeCLTE indicates CL.TE vulnerability (Content-Length wins on frontend).
	TypeCLTE
	// TypeTECL indicates TE.CL vulnerability (Transfer-Encoding wins on frontend).
	TypeTECL
	// TypeTETE indicates TE.TE vulnerability (obfuscated Transfer-Encoding).
	TypeTETE
)

// String returns the string representation of SmugglingType.
func (s SmugglingType) String() string {
	switch s {
	case TypeCLTE:
		return "CL.TE"
	case TypeTECL:
		return "TE.CL"
	case TypeTETE:
		return "TE.TE"
	default:
		return "Unknown"
	}
}

// Result contains the result of a smuggling detection test.
type Result struct {
	// Vulnerable indicates if the target is vulnerable.
	Vulnerable bool

	// Type indicates the smuggling type detected.
	Type SmugglingType

	// Confidence is a score from 0.0 to 1.0 indicating detection confidence.
	Confidence float64

	// Evidence contains description of what was detected.
	Evidence string

	// TimingDiff is the timing differential observed (for timing-based detection).
	TimingDiff time.Duration

	// FrontendBehavior describes how the frontend processed the request.
	FrontendBehavior string

	// BackendBehavior describes how the backend processed the request.
	BackendBehavior string

	// Request contains the raw request that triggered detection.
	Request string

	// Response contains the raw response received.
	Response string
}

// Config contains configuration for the smuggling detector.
type Config struct {
	// Timeout is the maximum time to wait for responses.
	Timeout time.Duration

	// TimingThreshold is the minimum timing differential to consider significant.
	TimingThreshold time.Duration

	// MaxRetries is the number of retry attempts for each test.
	MaxRetries int

	// EnableTimingTest enables timing-based detection.
	EnableTimingTest bool

	// EnableDiffTest enables differential response detection.
	EnableDiffTest bool

	// UserAgent is the User-Agent header to use in requests.
	UserAgent string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Timeout:          time.Second * 10,
		TimingThreshold:  time.Second * 5,
		MaxRetries:       3,
		EnableTimingTest: true,
		EnableDiffTest:   true,
		UserAgent:        "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
	}
}

// Validate checks if the config is valid.
func (c *Config) Validate() error {
	if c.Timeout == 0 {
		return errors.New("timeout must be greater than zero")
	}
	if c.TimingThreshold == 0 {
		return errors.New("timing threshold must be greater than zero")
	}
	return nil
}

// OWASPMapping contains OWASP framework references for this vulnerability.
type OWASPMapping struct {
	WSTG     []string
	Top10    []string
	APITop10 []string
	CWE      []string
}

// Response represents a parsed HTTP response.
type Response struct {
	StatusCode int
	Status     string
	Headers    map[string]string
	Body       string
	Raw        string
}
