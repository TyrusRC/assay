// Package matchers provides response matching capabilities for nuclei templates.
package matchers

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
)

// Response represents an HTTP response for matching.
type Response struct {
	StatusCode    int
	Headers       map[string]string
	Body          string
	ContentLength int
	ContentType   string
	URL           string
	Protocol      string // For interactsh matching
	Raw           string
	Duration      time.Duration // Response time for time-based detection
}

// MatcherEngine evaluates matchers against responses.
type MatcherEngine struct {
	// Cache for compiled regex patterns
	regexCache map[string]*regexp.Regexp
	regexMu    sync.RWMutex

	// DSL expression evaluator
	dslEngine *DSLEngine
}

// New creates a new matcher engine.
func New() *MatcherEngine {
	return &MatcherEngine{
		regexCache: make(map[string]*regexp.Regexp),
		dslEngine:  NewDSLEngine(),
	}
}

// MatchResult contains the result of matching.
type MatchResult struct {
	Matched  bool
	Name     string
	Extracts []string
}

// Match evaluates a single matcher against a response.
func (e *MatcherEngine) Match(m *templates.Matcher, resp *Response, data map[string]interface{}) *MatchResult {
	result := &MatchResult{
		Name: m.Name,
	}

	var matched bool
	switch m.Type {
	case "word":
		matched = e.matchWord(m, resp)
	case "regex":
		matched, result.Extracts = e.matchRegex(m, resp)
	case "status":
		matched = e.matchStatus(m, resp)
	case "size":
		matched = e.matchSize(m, resp)
	case "binary":
		matched = e.matchBinary(m, resp)
	case "dsl":
		matched = e.matchDSL(m, resp, data)
	case "xpath":
		matched, result.Extracts = e.matchXPath(m, resp)
	case "time":
		matched = e.matchTime(m, resp, data)
	default:
		return result
	}

	// Handle negative matching
	if m.Negative {
		matched = !matched
	}

	result.Matched = matched
	return result
}

// MatchAll evaluates all matchers with the specified condition.
func (e *MatcherEngine) MatchAll(matchers []templates.Matcher, condition string, resp *Response, data map[string]interface{}) (bool, map[string][]string) {
	if len(matchers) == 0 {
		return true, nil
	}

	extracts := make(map[string][]string)
	condition = strings.ToLower(condition)
	if condition == "" {
		condition = "or" // Default to OR
	}

	var matchedCount int
	var nonInternalCount int
	for _, m := range matchers {
		// Skip internal matchers for final result
		if m.Internal {
			continue
		}

		nonInternalCount++
		result := e.Match(&m, resp, data)
		if result.Matched {
			matchedCount++
			if m.Name != "" && len(result.Extracts) > 0 {
				extracts[m.Name] = result.Extracts
			}
		}

		// Short-circuit for AND condition
		if condition == "and" && !result.Matched {
			return false, nil
		}

		// Short-circuit for OR condition
		if condition == "or" && result.Matched {
			return true, extracts
		}
	}

	if condition == "and" {
		return matchedCount == nonInternalCount, extracts
	}

	return matchedCount > 0, extracts
}

