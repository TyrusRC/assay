package matchers

import "fmt"

// DSLEngine provides an enhanced DSL evaluator for nuclei templates.
type DSLEngine struct {
	// Function registry
	functions map[string]DSLFunction
}

// DSLFunction represents a DSL function signature.
type DSLFunction func(args []interface{}, ctx map[string]interface{}) interface{}

// NewDSLEngine creates a new DSL engine with all registered functions.
func NewDSLEngine() *DSLEngine {
	e := &DSLEngine{
		functions: make(map[string]DSLFunction),
	}
	e.registerFunctions()
	e.registerExtendedFunctions()
	return e
}

// registerFunctions registers all built-in DSL functions.
func (e *DSLEngine) registerFunctions() {
	// String functions
	e.functions["startsWith"] = dslStartsWith
	e.functions["endsWith"] = dslEndsWith
	e.functions["toUpper"] = dslToUpper
	e.functions["toLower"] = dslToLower
	e.functions["trim"] = dslTrim
	e.functions["replace"] = dslReplace
	e.functions["split"] = dslSplit
	e.functions["contains"] = dslContains
	e.functions["len"] = dslLen

	// Encoding functions
	e.functions["base64Encode"] = dslBase64Encode
	e.functions["base64Decode"] = dslBase64Decode
	e.functions["urlEncode"] = dslURLEncode
	e.functions["urlDecode"] = dslURLDecode
	e.functions["htmlEncode"] = dslHTMLEncode
	e.functions["htmlDecode"] = dslHTMLDecode

	// Hash functions
	e.functions["md5"] = dslMD5
	e.functions["sha1"] = dslSHA1
	e.functions["sha256"] = dslSHA256

	// List functions
	e.functions["join"] = dslJoin

	// Regex function
	e.functions["regex_match"] = dslRegexMatch
}

// Evaluate evaluates a DSL expression and returns true/false.
func (e *DSLEngine) Evaluate(expr string, ctx map[string]interface{}) bool {
	result := e.evaluateExpr(expr, ctx)
	if b, ok := result.(bool); ok {
		return b
	}
	return false
}

// EvaluateString evaluates a DSL expression and returns a string result.
func (e *DSLEngine) EvaluateString(expr string, ctx map[string]interface{}) string {
	result := e.evaluateExpr(expr, ctx)
	if s, ok := result.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", result)
}
