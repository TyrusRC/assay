package cspt

import "strings"

// sinkCall is one request-issuing call extracted from JS source.
type sinkCall struct {
	name string // normalized call name, e.g. "fetch", "XMLHttpRequest.open"
	args string // raw text inside the call's parentheses
	text string // the call snippet, for evidence
}

// urlArg returns the call's URL argument (argument 1 for XHR open, which takes
// (method, url); argument 0 otherwise).
func (c sinkCall) urlArg() string {
	idx := 0
	if c.name == "XMLHttpRequest.open" {
		idx = 1
	}
	args := splitTopLevelComma(c.args)
	if idx >= len(args) {
		return ""
	}
	return strings.TrimSpace(args[idx])
}

// findSinkCalls locates every request-issuing call and captures its argument
// list via balanced-parenthesis scanning.
func findSinkCalls(js string) []sinkCall {
	locs := sinkRe.FindAllStringSubmatchIndex(js, -1)
	calls := make([]sinkCall, 0, len(locs))
	for _, loc := range locs {
		raw := js[loc[2]:loc[3]]
		name := normalizeSinkName(raw)
		if name == "" {
			continue
		}
		// loc[1] is the index just past the matched "(".
		args, end := readBalanced(js, loc[1]-1)
		if end < 0 {
			continue
		}
		calls = append(calls, sinkCall{
			name: name,
			args: args,
			text: name + "(" + args + ")",
		})
	}
	return calls
}

// normalizeSinkName maps a matched keyword to a stable display name, returning
// "" for the bare XMLHttpRequest token (the real sink is its .open call).
func normalizeSinkName(raw string) string {
	switch raw {
	case "XMLHttpRequest":
		return ""
	case ".open":
		return "XMLHttpRequest.open"
	case ".ajax":
		return "$.ajax"
	default:
		return raw
	}
}

// readBalanced returns the text inside the parentheses that open at openParen,
// and the index just past the closing parenthesis (-1 if unbalanced). Quoted
// strings are skipped so brackets inside literals don't affect nesting.
func readBalanced(s string, openParen int) (inner string, end int) {
	if openParen < 0 || openParen >= len(s) || s[openParen] != '(' {
		return "", -1
	}
	depth := 0
	var quote byte
	start := openParen + 1
	for i := openParen; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return s[start:i], i + 1
			}
		}
	}
	return "", -1
}

// splitTopLevelComma splits an argument list on commas outside of quotes,
// brackets, and parentheses.
func splitTopLevelComma(args string) []string {
	var parts []string
	var cur strings.Builder
	depth := 0
	var quote byte
	for i := 0; i < len(args); i++ {
		c := args[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"' || c == '`':
			quote = c
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	parts = append(parts, cur.String())
	return parts
}
