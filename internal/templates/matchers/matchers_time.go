package matchers

import (
	"strings"
	"time"

	"github.com/TyrusRC/swiss-knife-for-web-security/internal/templates"
)

// matchTime evaluates time-based matchers for timing attacks detection.
func (e *MatcherEngine) matchTime(m *templates.Matcher, resp *Response, data map[string]interface{}) bool {
	condition := strings.ToLower(m.Condition)
	if condition == "" {
		condition = "or"
	}

	var baseline time.Duration
	if b, ok := data["baseline_duration"].(time.Duration); ok {
		baseline = b
	}

	var tolerance time.Duration = 100 * time.Millisecond
	if t, ok := data["time_tolerance"].(time.Duration); ok {
		tolerance = t
	}

	var multiplier float64 = 1.0
	if mult, ok := data["time_multiplier"].(float64); ok {
		multiplier = mult
	}

	matchCount := 0
	for _, expr := range m.DSL {
		if e.evaluateTimeExpression(expr, resp.Duration, baseline, tolerance, multiplier) {
			matchCount++
			if condition == "or" {
				return true
			}
		} else if condition == "and" {
			return false
		}
	}

	if condition == "and" {
		return matchCount == len(m.DSL)
	}
	return matchCount > 0
}

// evaluateTimeExpression evaluates a single time comparison expression.
func (e *MatcherEngine) evaluateTimeExpression(expr string, duration, baseline, tolerance time.Duration, multiplier float64) bool {
	expr = strings.TrimSpace(expr)

	var operator string
	var valueStr string

	if strings.Contains(expr, "baseline") {
		switch {
		case strings.Contains(expr, ">="):
			operator = ">="
		case strings.Contains(expr, "<="):
			operator = "<="
		case strings.Contains(expr, ">"):
			operator = ">"
		case strings.Contains(expr, "<"):
			operator = "<"
		case strings.Contains(expr, "=="):
			operator = "=="
		}

		threshold := time.Duration(float64(baseline) * multiplier)
		return e.compareTime(duration, threshold, tolerance, operator)
	}

	switch {
	case strings.HasPrefix(expr, ">="):
		operator = ">="
		valueStr = strings.TrimSpace(expr[2:])
	case strings.HasPrefix(expr, "<="):
		operator = "<="
		valueStr = strings.TrimSpace(expr[2:])
	case strings.HasPrefix(expr, "=="):
		operator = "=="
		valueStr = strings.TrimSpace(expr[2:])
	case strings.HasPrefix(expr, ">"):
		operator = ">"
		valueStr = strings.TrimSpace(expr[1:])
	case strings.HasPrefix(expr, "<"):
		operator = "<"
		valueStr = strings.TrimSpace(expr[1:])
	default:
		return false
	}

	threshold, err := time.ParseDuration(valueStr)
	if err != nil {
		return false
	}

	return e.compareTime(duration, threshold, tolerance, operator)
}

// compareTime performs time comparison with the given operator.
func (e *MatcherEngine) compareTime(duration, threshold, tolerance time.Duration, operator string) bool {
	switch operator {
	case ">":
		return duration > threshold
	case "<":
		return duration < threshold
	case ">=":
		return duration >= threshold
	case "<=":
		return duration <= threshold
	case "==":
		diff := duration - threshold
		if diff < 0 {
			diff = -diff
		}
		return diff <= tolerance
	default:
		return false
	}
}
