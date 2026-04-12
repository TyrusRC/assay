package executor

import (
	"regexp"
	"strings"
)

// flowStepPattern matches protocol calls like http(1), dns(), tcp(2).
var flowStepPattern = regexp.MustCompile(`(http|dns|ssl|tcp|network|headless|websocket|whois)\((\d*)\)`)

// FlowStep represents a single protocol execution step in a flow expression.
type FlowStep struct {
	// Protocol is the protocol name: http, dns, ssl, tcp, network, headless, websocket, whois.
	Protocol string
	// Index is the 1-based block index to execute. 0 means execute all blocks.
	Index int
	// Operator is the logical operator preceding this step: "", "&&", or "||".
	Operator string
}

// FlowEngine parses and evaluates template flow expressions.
type FlowEngine struct{}

// NewFlowEngine creates a new FlowEngine.
func NewFlowEngine() *FlowEngine {
	return &FlowEngine{}
}

// Parse parses a flow expression into an ordered slice of FlowSteps.
// Example: "http(1) && http(2)" -> [{Protocol:"http",Index:1}, {Protocol:"http",Index:2,Operator:"&&"}]
func (fe *FlowEngine) Parse(flow string) []FlowStep {
	if flow == "" {
		return nil
	}

	matches := flowStepPattern.FindAllStringSubmatchIndex(flow, -1)
	if len(matches) == 0 {
		return nil
	}

	steps := make([]FlowStep, 0, len(matches))
	prevEnd := 0

	for i, loc := range matches {
		start := loc[0]
		end := loc[1]

		fullMatch := flow[loc[0]:loc[1]]
		_ = fullMatch

		protocol := flow[loc[2]:loc[3]]

		var index int
		if loc[4] != -1 && loc[5] != -1 {
			indexStr := flow[loc[4]:loc[5]]
			if indexStr != "" {
				for _, c := range indexStr {
					index = index*10 + int(c-'0')
				}
			}
		}

		var operator string
		if i > 0 {
			between := strings.TrimSpace(flow[prevEnd:start])
			if strings.HasSuffix(between, "&&") {
				operator = "&&"
			} else if strings.HasSuffix(between, "||") {
				operator = "||"
			}
		}

		steps = append(steps, FlowStep{
			Protocol: protocol,
			Index:    index,
			Operator: operator,
		})

		prevEnd = end
	}

	return steps
}

// ShouldContinue determines whether execution should continue based on the
// operator and the result of the previous step.
func (fe *FlowEngine) ShouldContinue(operator string, previousMatched bool) bool {
	switch operator {
	case "&&":
		// AND: continue only if the previous step matched
		return previousMatched
	case "||":
		// OR: continue only if the previous step did NOT match
		return !previousMatched
	default:
		return true
	}
}
