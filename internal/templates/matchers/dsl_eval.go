package matchers

import (
	"strconv"
	"strings"
)

// maxExprDepth is the maximum recursion depth for DSL expression evaluation.
const maxExprDepth = 64

// evaluateExpr evaluates an expression and returns its value.
func (e *DSLEngine) evaluateExpr(expr string, ctx map[string]interface{}) interface{} {
	return e.evaluateExprDepth(expr, ctx, 0)
}

// evaluateExprDepth evaluates an expression with recursion depth tracking.
func (e *DSLEngine) evaluateExprDepth(expr string, ctx map[string]interface{}, depth int) interface{} {
	if depth > maxExprDepth {
		return nil
	}
	expr = strings.TrimSpace(expr)

	// Handle logical operators (lowest precedence)
	if result, handled := e.evaluateLogical(expr, ctx); handled {
		return result
	}

	// Handle comparison operators
	if result, handled := e.evaluateComparison(expr, ctx); handled {
		return result
	}

	// Handle NOT operator
	if strings.HasPrefix(expr, "!") {
		inner := strings.TrimPrefix(expr, "!")
		result := e.evaluateExpr(inner, ctx)
		if b, ok := result.(bool); ok {
			return !b
		}
		return false
	}

	// Handle function calls
	if result, handled := e.evaluateFunction(expr, ctx); handled {
		return result
	}

	// Handle array index access
	if result, handled := e.evaluateArrayAccess(expr, ctx); handled {
		return result
	}

	// Handle literals
	if result, handled := e.evaluateLiteral(expr); handled {
		return result
	}

	// Handle variable references
	return e.resolveVariable(expr, ctx)
}

// evaluateLogical handles && and || operators.
func (e *DSLEngine) evaluateLogical(expr string, ctx map[string]interface{}) (interface{}, bool) {
	// Find the lowest precedence logical operator outside parentheses
	depth := 0
	for i := len(expr) - 1; i >= 0; i-- {
		switch expr[i] {
		case ')':
			depth++
		case '(':
			depth--
		case '|':
			if depth == 0 && i > 0 && expr[i-1] == '|' {
				left := e.evaluateExpr(expr[:i-1], ctx)
				right := e.evaluateExpr(expr[i+1:], ctx)
				leftBool, _ := left.(bool)
				rightBool, _ := right.(bool)
				return leftBool || rightBool, true
			}
		case '&':
			if depth == 0 && i > 0 && expr[i-1] == '&' {
				left := e.evaluateExpr(expr[:i-1], ctx)
				right := e.evaluateExpr(expr[i+1:], ctx)
				leftBool, _ := left.(bool)
				rightBool, _ := right.(bool)
				return leftBool && rightBool, true
			}
		}
	}
	return nil, false
}

// evaluateComparison handles ==, !=, >, <, >=, <= operators.
func (e *DSLEngine) evaluateComparison(expr string, ctx map[string]interface{}) (interface{}, bool) {
	operators := []string{"==", "!=", ">=", "<=", ">", "<"}

	for _, op := range operators {
		// Find operator outside parentheses and quotes
		idx := e.findOperatorOutside(expr, op)
		if idx != -1 {
			left := e.evaluateExpr(expr[:idx], ctx)
			right := e.evaluateExpr(expr[idx+len(op):], ctx)
			return e.compare(left, right, op), true
		}
	}
	return nil, false
}

// findOperatorOutside finds an operator outside parentheses and quotes.
func (e *DSLEngine) findOperatorOutside(expr, op string) int {
	depth := 0
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(expr)-len(op)+1; i++ {
		c := expr[i]

		if !inQuote && (c == '"' || c == '\'') {
			inQuote = true
			quoteChar = c
		} else if inQuote && c == quoteChar {
			inQuote = false
		} else if !inQuote {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
			} else if depth == 0 && strings.HasPrefix(expr[i:], op) {
				// Make sure this isn't part of a longer operator
				if op == ">" && i+1 < len(expr) && expr[i+1] == '=' {
					continue
				}
				if op == "<" && i+1 < len(expr) && expr[i+1] == '=' {
					continue
				}
				if op == "=" && i > 0 && (expr[i-1] == '!' || expr[i-1] == '>' || expr[i-1] == '<' || expr[i-1] == '=') {
					continue
				}
				return i
			}
		}
	}
	return -1
}

// compare performs comparison between two values.
func (e *DSLEngine) compare(left, right interface{}, op string) bool {
	// Handle string comparison
	leftStr, leftIsStr := left.(string)
	rightStr, rightIsStr := right.(string)
	if leftIsStr && rightIsStr {
		switch op {
		case "==":
			return leftStr == rightStr
		case "!=":
			return leftStr != rightStr
		case ">":
			return leftStr > rightStr
		case "<":
			return leftStr < rightStr
		case ">=":
			return leftStr >= rightStr
		case "<=":
			return leftStr <= rightStr
		}
	}

	// Handle numeric comparison
	leftNum := toFloat64(left)
	rightNum := toFloat64(right)

	switch op {
	case "==":
		return leftNum == rightNum
	case "!=":
		return leftNum != rightNum
	case ">":
		return leftNum > rightNum
	case "<":
		return leftNum < rightNum
	case ">=":
		return leftNum >= rightNum
	case "<=":
		return leftNum <= rightNum
	}
	return false
}

// evaluateFunction handles function calls.
func (e *DSLEngine) evaluateFunction(expr string, ctx map[string]interface{}) (interface{}, bool) {
	// Handle parenthesized expressions
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		return e.evaluateExpr(expr[1:len(expr)-1], ctx), true
	}

	// Find function name and arguments
	parenIdx := strings.Index(expr, "(")
	if parenIdx == -1 || !strings.HasSuffix(expr, ")") {
		return nil, false
	}

	funcName := expr[:parenIdx]
	argsStr := expr[parenIdx+1 : len(expr)-1]

	fn, exists := e.functions[funcName]
	if !exists {
		return nil, false
	}

	args := e.parseArgs(argsStr, ctx)
	return fn(args, ctx), true
}

// parseArgs parses function arguments.
func (e *DSLEngine) parseArgs(argsStr string, ctx map[string]interface{}) []interface{} {
	var args []interface{}
	var current strings.Builder
	depth := 0
	inQuote := false
	quoteChar := byte(0)

	for i := 0; i < len(argsStr); i++ {
		c := argsStr[i]

		if !inQuote && (c == '"' || c == '\'') {
			inQuote = true
			quoteChar = c
			current.WriteByte(c)
		} else if inQuote && c == quoteChar {
			inQuote = false
			current.WriteByte(c)
		} else if !inQuote && c == '(' {
			depth++
			current.WriteByte(c)
		} else if !inQuote && c == ')' {
			depth--
			current.WriteByte(c)
		} else if !inQuote && depth == 0 && c == ',' {
			args = append(args, e.evaluateExpr(current.String(), ctx))
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}

	if current.Len() > 0 {
		args = append(args, e.evaluateExpr(current.String(), ctx))
	}

	return args
}

// evaluateArrayAccess handles array index access like split(url, "/")[2].
func (e *DSLEngine) evaluateArrayAccess(expr string, ctx map[string]interface{}) (interface{}, bool) {
	bracketIdx := strings.LastIndex(expr, "[")
	if bracketIdx == -1 || !strings.HasSuffix(expr, "]") {
		return nil, false
	}

	arrayExpr := expr[:bracketIdx]
	indexStr := expr[bracketIdx+1 : len(expr)-1]

	array := e.evaluateExpr(arrayExpr, ctx)
	index, err := strconv.Atoi(strings.TrimSpace(indexStr))
	if err != nil {
		return nil, false
	}

	// Handle string slice
	if arr, ok := array.([]string); ok {
		if index >= 0 && index < len(arr) {
			return arr[index], true
		}
		return "", true
	}

	// Handle interface slice
	if arr, ok := array.([]interface{}); ok {
		if index >= 0 && index < len(arr) {
			return arr[index], true
		}
		return "", true
	}

	return nil, false
}

// evaluateLiteral handles literal values (strings, numbers).
func (e *DSLEngine) evaluateLiteral(expr string) (interface{}, bool) {
	// Handle string literals
	if (strings.HasPrefix(expr, `"`) && strings.HasSuffix(expr, `"`)) ||
		(strings.HasPrefix(expr, `'`) && strings.HasSuffix(expr, `'`)) {
		return expr[1 : len(expr)-1], true
	}

	// Handle numeric literals
	if num, err := strconv.ParseFloat(expr, 64); err == nil {
		// ParseFloat handles both integer and floating-point strings
		return num, true
	}

	// Handle boolean literals
	if expr == "true" {
		return true, true
	}
	if expr == "false" {
		return false, true
	}

	return nil, false
}

// resolveVariable resolves a variable from context.
func (e *DSLEngine) resolveVariable(name string, ctx map[string]interface{}) interface{} {
	name = strings.TrimSpace(name)
	if v, ok := ctx[name]; ok {
		return v
	}
	return nil
}

// toFloat64 converts various types to float64.
func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case int:
		return float64(n)
	case int32:
		return float64(n)
	case int64:
		return float64(n)
	case uint:
		return float64(n)
	case uint32:
		return float64(n)
	case uint64:
		return float64(n)
	case float32:
		return float64(n)
	case float64:
		return n
	case string:
		if f, err := strconv.ParseFloat(n, 64); err == nil {
			return f
		}
	}
	return 0
}
