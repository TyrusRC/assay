package matchers

import "testing"

// Nuclei templates call DSL helpers in snake_case; assay registers many in
// camelCase. The snake->camel fallback must resolve both.
func TestDSL_SnakeToCamelFallback(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}
	// url_encode has no explicit snake alias, but urlEncode is registered.
	if !dsl.Evaluate("url_encode(\"ab\") == \"ab\"", ctx) {
		t.Error("url_encode snake->camel fallback did not resolve")
	}
}

func TestDSL_AddedNucleiFunctions(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}
	exprs := []string{
		"substr(\"abcdef\", 1, 4) == \"bcd\"",
		"substr(\"abcdef\", 3) == \"def\"",
		"to_number(\"42\") == 42",
		"crc32(\"abc\") == 891568578",
	}
	for _, e := range exprs {
		if !dsl.Evaluate(e, ctx) {
			t.Errorf("expected true: %s", e)
		}
	}
}
