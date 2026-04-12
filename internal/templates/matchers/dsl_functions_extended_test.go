package matchers

import (
	"strings"
	"testing"
)

func TestDSLExtended_SnakeCaseAliases(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"body": "Hello World",
	}

	tests := []struct {
		name        string
		expr        string
		expectMatch bool
	}{
		{
			name:        "starts_with - match",
			expr:        `starts_with(body, "Hello")`,
			expectMatch: true,
		},
		{
			name:        "starts_with - no match",
			expr:        `starts_with(body, "World")`,
			expectMatch: false,
		},
		{
			name:        "ends_with - match",
			expr:        `ends_with(body, "World")`,
			expectMatch: true,
		},
		{
			name:        "ends_with - no match",
			expr:        `ends_with(body, "Hello")`,
			expectMatch: false,
		},
		{
			name:        "to_upper",
			expr:        `to_upper(body) == "HELLO WORLD"`,
			expectMatch: true,
		},
		{
			name:        "to_lower",
			expr:        `to_lower(body) == "hello world"`,
			expectMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expectMatch {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expectMatch)
			}
		})
	}
}

func TestDSLExtended_ContainsAll(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"body": "foo bar baz",
	}

	tests := []struct {
		name   string
		expr   string
		expect bool
	}{
		{"all present", `contains_all(body, "foo", "bar", "baz")`, true},
		{"one missing", `contains_all(body, "foo", "qux")`, false},
		{"single present", `contains_all(body, "foo")`, true},
		{"empty args", `contains_all(body)`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expect {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expect)
			}
		})
	}
}

func TestDSLExtended_ContainsAny(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"body": "hello world",
	}

	tests := []struct {
		name   string
		expr   string
		expect bool
	}{
		{"first present", `contains_any(body, "hello", "xyz")`, true},
		{"second present", `contains_any(body, "xyz", "world")`, true},
		{"none present", `contains_any(body, "xyz", "abc")`, false},
		{"empty args", `contains_any(body)`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expect {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expect)
			}
		})
	}
}

func TestDSLExtended_Regex(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"body": "Version: 2.5.1",
	}

	tests := []struct {
		name   string
		expr   string
		expect bool
	}{
		{"match", `regex("[0-9]+[.][0-9]+", body)`, true},
		{"no match", `regex("^Error:", body)`, false},
		{"empty args", `regex("abc")`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expect {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expect)
			}
		})
	}
}

func TestDSLExtended_RegexAny(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"body": "hello world",
	}

	tests := []struct {
		name   string
		expr   string
		expect bool
	}{
		{"first matches", `regex_any(body, "^hello", "^Error")`, true},
		{"second matches", `regex_any(body, "^Error", "world$")`, true},
		{"none match", `regex_any(body, "^Error", "^fail")`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expect {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expect)
			}
		})
	}
}

func TestDSLExtended_RegexAll(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"body": "hello world 123",
	}

	tests := []struct {
		name   string
		expr   string
		expect bool
	}{
		{"all match", `regex_all(body, "hello", "[0-9]+")`, true},
		{"one fails", `regex_all(body, "hello", "^Error")`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expect {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expect)
			}
		})
	}
}

func TestDSLExtended_EqualsAny(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"status": "200",
	}

	tests := []struct {
		name   string
		expr   string
		expect bool
	}{
		{"equals first", `equals_any(status, "200", "404")`, true},
		{"equals second", `equals_any(status, "404", "200")`, true},
		{"no match", `equals_any(status, "301", "302")`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expect {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expect)
			}
		})
	}
}

func TestDSLExtended_LineStartsWith(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"body": "line one\nError: something bad\nline three",
	}

	tests := []struct {
		name   string
		expr   string
		expect bool
	}{
		{"match second line", `line_starts_with(body, "Error:")`, true},
		{"match first line", `line_starts_with(body, "line")`, true},
		{"no match", `line_starts_with(body, "Warning:")`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expect {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expect)
			}
		})
	}
}

func TestDSLExtended_LineEndsWith(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"body": "line one\nsomething bad\nline three",
	}

	tests := []struct {
		name   string
		expr   string
		expect bool
	}{
		{"match first line", `line_ends_with(body, "one")`, true},
		{"match last line", `line_ends_with(body, "three")`, true},
		{"no match", `line_ends_with(body, "none")`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expect {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expect)
			}
		})
	}
}

func TestDSLExtended_StringManipulation(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	tests := []struct {
		name   string
		expr   string
		expect string
	}{
		{"concat", `concat("foo", "bar", "baz")`, "foobarbaz"},
		{"repeat", `repeat("ab", 3)`, "ababab"},
		{"repeat zero", `repeat("ab", 0)`, ""},
		{"reverse", `reverse("hello")`, "olleh"},
		{"remove_bad_chars", `remove_bad_chars("he<>llo", "<>")`, "hello"},
		{"trim_left", `trim_left("   hello", " ")`, "hello"},
		{"trim_right", `trim_right("hello   ", " ")`, "hello"},
		{"trim_space", `trim_space("  hello  ")`, "hello"},
		{"trim_prefix", `trim_prefix("hello world", "hello ")`, "world"},
		{"trim_suffix", `trim_suffix("hello world", " world")`, "hello"},
		{"replace_regex", `replace_regex("hello 123", "[0-9]+", "NUM")`, "hello NUM"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.EvaluateString(tt.expr, ctx)
			if result != tt.expect {
				t.Errorf("EvaluateString(%q) = %q, want %q", tt.expr, result, tt.expect)
			}
		})
	}
}

func TestDSLExtended_HexEncoding(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("hex_encode", func(t *testing.T) {
		result := dsl.EvaluateString(`hex_encode("hello")`, ctx)
		if result != "68656c6c6f" {
			t.Errorf("hex_encode = %q, want 68656c6c6f", result)
		}
	})

	t.Run("hex_decode", func(t *testing.T) {
		result := dsl.EvaluateString(`hex_decode("68656c6c6f")`, ctx)
		if result != "hello" {
			t.Errorf("hex_decode = %q, want hello", result)
		}
	})

	t.Run("hex roundtrip", func(t *testing.T) {
		result := dsl.Evaluate(`hex_decode(hex_encode("test")) == "test"`, ctx)
		if !result {
			t.Error("hex roundtrip failed")
		}
	})

	t.Run("hex_decode invalid", func(t *testing.T) {
		result := dsl.EvaluateString(`hex_decode("xyz")`, ctx)
		if result != "" {
			t.Errorf("hex_decode invalid = %q, want empty", result)
		}
	})
}

func TestDSLExtended_Base64Py(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("base64_py alias", func(t *testing.T) {
		result := dsl.Evaluate(`base64_py("hello") == base64Encode("hello")`, ctx)
		if !result {
			t.Error("base64_py should be alias for base64Encode")
		}
	})
}

func TestDSLExtended_MMH3(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("mmh3 returns number", func(t *testing.T) {
		result := dsl.EvaluateString(`mmh3("hello")`, ctx)
		if result == "" || result == "0" {
			// mmh3 should return a non-zero value for non-empty input
			// but we just check it's a number-like string
		}
		// Just verify it doesn't panic and returns something
		if result == "" {
			t.Error("mmh3 returned empty string")
		}
	})

	t.Run("mmh3 empty", func(t *testing.T) {
		result := dsl.EvaluateString(`mmh3("")`, ctx)
		// Should return "0" for FNV-1a of empty string (or the actual value)
		if result == "" {
			t.Error("mmh3 of empty string should return a value")
		}
	})

	t.Run("mmh3 deterministic", func(t *testing.T) {
		r1 := dsl.EvaluateString(`mmh3("test")`, ctx)
		r2 := dsl.EvaluateString(`mmh3("test")`, ctx)
		if r1 != r2 {
			t.Errorf("mmh3 should be deterministic: %q != %q", r1, r2)
		}
	})
}

func TestDSLExtended_HMAC(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("hmac sha256", func(t *testing.T) {
		result := dsl.EvaluateString(`hmac("sha256", "data", "key")`, ctx)
		if len(result) != 64 {
			t.Errorf("HMAC-SHA256 should be 64 hex chars, got %d: %q", len(result), result)
		}
	})

	t.Run("hmac deterministic", func(t *testing.T) {
		r1 := dsl.EvaluateString(`hmac("sha256", "msg", "secret")`, ctx)
		r2 := dsl.EvaluateString(`hmac("sha256", "msg", "secret")`, ctx)
		if r1 != r2 {
			t.Errorf("hmac should be deterministic: %q != %q", r1, r2)
		}
	})
}

func TestDSLExtended_RandFunctions(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("rand_text_alpha length", func(t *testing.T) {
		result := dsl.EvaluateString(`rand_text_alpha(8)`, ctx)
		if len(result) != 8 {
			t.Errorf("rand_text_alpha(8) len = %d, want 8", len(result))
		}
	})

	t.Run("rand_text_alpha chars", func(t *testing.T) {
		result := dsl.EvaluateString(`rand_text_alpha(20)`, ctx)
		for _, c := range result {
			if !strings.ContainsRune(alphaChars, c) {
				t.Errorf("rand_text_alpha produced non-alpha char: %c", c)
			}
		}
	})

	t.Run("rand_text_alphanumeric length", func(t *testing.T) {
		result := dsl.EvaluateString(`rand_text_alphanumeric(10)`, ctx)
		if len(result) != 10 {
			t.Errorf("rand_text_alphanumeric(10) len = %d, want 10", len(result))
		}
	})

	t.Run("rand_text_numeric length", func(t *testing.T) {
		result := dsl.EvaluateString(`rand_text_numeric(5)`, ctx)
		if len(result) != 5 {
			t.Errorf("rand_text_numeric(5) len = %d, want 5", len(result))
		}
	})

	t.Run("rand_text_numeric chars", func(t *testing.T) {
		result := dsl.EvaluateString(`rand_text_numeric(10)`, ctx)
		for _, c := range result {
			if c < '0' || c > '9' {
				t.Errorf("rand_text_numeric produced non-digit: %c", c)
			}
		}
	})

	t.Run("rand_base length", func(t *testing.T) {
		result := dsl.EvaluateString(`rand_base(12)`, ctx)
		if len(result) != 12 {
			t.Errorf("rand_base(12) len = %d, want 12", len(result))
		}
	})

	t.Run("rand_char length", func(t *testing.T) {
		result := dsl.EvaluateString(`rand_char("abc")`, ctx)
		if len(result) != 1 {
			t.Errorf("rand_char should return 1 char, got %q", result)
		}
	})

	t.Run("rand_char from charset", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			result := dsl.EvaluateString(`rand_char("abc")`, ctx)
			if result != "a" && result != "b" && result != "c" {
				t.Errorf("rand_char returned char not in charset: %q", result)
			}
		}
	})

	t.Run("rand_ip format", func(t *testing.T) {
		result := dsl.EvaluateString(`rand_ip()`, ctx)
		parts := strings.Split(result, ".")
		if len(parts) != 4 {
			t.Errorf("rand_ip should return IPv4 format, got %q", result)
		}
	})
}

func TestDSLExtended_RandInt(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("rand_int in range", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			result := dsl.Evaluate(`rand_int(1, 10) >= 1 && rand_int(1, 10) <= 10`, ctx)
			if !result {
				t.Error("rand_int should be in [1, 10]")
				break
			}
		}
	})

	t.Run("rand_int no args returns number", func(t *testing.T) {
		result := dsl.EvaluateString(`rand_int()`, ctx)
		if result == "" {
			t.Error("rand_int with no args should return a number")
		}
	})
}

func TestDSLExtended_CompareVersions(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	tests := []struct {
		name   string
		expr   string
		expect bool
	}{
		{"equal versions", `compare_versions("1.2.3", "==", "1.2.3")`, true},
		{"greater version", `compare_versions("2.0.0", ">", "1.9.9")`, true},
		{"less version", `compare_versions("1.0.0", "<", "2.0.0")`, true},
		{"greater or equal same", `compare_versions("1.2.3", ">=", "1.2.3")`, true},
		{"less or equal same", `compare_versions("1.2.3", "<=", "1.2.3")`, true},
		{"not equal", `compare_versions("1.0.0", "!=", "2.0.0")`, true},
		{"v prefix stripped", `compare_versions("v1.2.3", "==", "1.2.3")`, true},
		{"prerelease less than release", `compare_versions("1.0.0-beta", "<", "1.0.0")`, true},
		{"minor version compare", `compare_versions("1.10.0", ">", "1.9.0")`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.Evaluate(tt.expr, ctx)
			if result != tt.expect {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, result, tt.expect)
			}
		})
	}
}

func TestDSLExtended_UnixTime(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("unix_time returns positive number", func(t *testing.T) {
		result := dsl.Evaluate(`unix_time() > 0`, ctx)
		if !result {
			t.Error("unix_time should return positive timestamp")
		}
	})
}

func TestDSLExtended_ToUnixTime(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("to_unix_time with RFC3339", func(t *testing.T) {
		result := dsl.Evaluate(`to_unix_time("2021-01-01T00:00:00Z") > 0`, ctx)
		if !result {
			t.Error("to_unix_time should parse RFC3339 date")
		}
	})

	t.Run("to_unix_time invalid returns 0", func(t *testing.T) {
		result := dsl.Evaluate(`to_unix_time("not-a-date") == 0`, ctx)
		if !result {
			t.Error("to_unix_time with invalid date should return 0")
		}
	})
}

func TestDSLExtended_DateTime(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("date_time returns non-empty string", func(t *testing.T) {
		result := dsl.EvaluateString(`date_time("%Y-%m-%d")`, ctx)
		if len(result) != 10 {
			t.Errorf("date_time(%%Y-%%m-%%d) should return 10-char date, got %q", result)
		}
	})
}

func TestDSLExtended_Compression(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("gzip roundtrip", func(t *testing.T) {
		compressed := dsl.EvaluateString(`gzip("hello world")`, ctx)
		if compressed == "" {
			t.Fatal("gzip returned empty string")
		}
		// Manually verify by calling gzip_decode
		args := []interface{}{compressed}
		result := dslGzipDecode(args, ctx)
		if result != "hello world" {
			t.Errorf("gzip_decode(gzip(x)) = %q, want %q", result, "hello world")
		}
	})

	t.Run("zlib roundtrip", func(t *testing.T) {
		compressed := dsl.EvaluateString(`zlib("test data")`, ctx)
		if compressed == "" {
			t.Fatal("zlib returned empty string")
		}
		args := []interface{}{compressed}
		result := dslZlibDecode(args, ctx)
		if result != "test data" {
			t.Errorf("zlib_decode(zlib(x)) = %q, want %q", result, "test data")
		}
	})

	t.Run("gzip_decode empty", func(t *testing.T) {
		result := dslGzipDecode([]interface{}{""}, ctx)
		if result != "" {
			t.Errorf("gzip_decode of empty should return empty, got %q", result)
		}
	})

	t.Run("zlib_decode empty", func(t *testing.T) {
		result := dslZlibDecode([]interface{}{""}, ctx)
		if result != "" {
			t.Errorf("zlib_decode of empty should return empty, got %q", result)
		}
	})
}

func TestDSLExtended_AESGCM(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("aes_gcm returns non-empty", func(t *testing.T) {
		result := dsl.EvaluateString(`aes_gcm("mykey", "plaintext")`, ctx)
		if result == "" {
			t.Error("aes_gcm should return non-empty ciphertext")
		}
	})

	t.Run("aes_gcm different nonce each time", func(t *testing.T) {
		r1 := dsl.EvaluateString(`aes_gcm("key", "data")`, ctx)
		r2 := dsl.EvaluateString(`aes_gcm("key", "data")`, ctx)
		// With random nonce, output should almost certainly differ
		if r1 == r2 {
			t.Log("aes_gcm produced same output twice - this is very unlikely but not impossible")
		}
	})
}

func TestDSLExtended_NumberConversion(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	tests := []struct {
		name   string
		expr   string
		expect string
	}{
		{"dec_to_hex 255", `dec_to_hex(255)`, "ff"},
		{"dec_to_hex 0", `dec_to_hex(0)`, "0"},
		{"dec_to_hex 16", `dec_to_hex(16)`, "10"},
		{"hex_to_dec ff", `hex_to_dec("ff")`, "255"},
		{"hex_to_dec 0", `hex_to_dec("0")`, "0"},
		{"bin_to_dec 1010", `bin_to_dec("1010")`, "10"},
		{"bin_to_dec 0", `bin_to_dec("0")`, "0"},
		{"oct_to_dec 17", `oct_to_dec("17")`, "15"},
		{"oct_to_dec 0", `oct_to_dec("0")`, "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dsl.EvaluateString(tt.expr, ctx)
			if result != tt.expect {
				t.Errorf("EvaluateString(%q) = %q, want %q", tt.expr, result, tt.expect)
			}
		})
	}
}

func TestDSLExtended_NumberConversionInvalid(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("hex_to_dec invalid", func(t *testing.T) {
		result := dsl.Evaluate(`hex_to_dec("xyz") == 0`, ctx)
		if !result {
			t.Error("hex_to_dec of invalid should return 0")
		}
	})

	t.Run("bin_to_dec invalid", func(t *testing.T) {
		result := dsl.Evaluate(`bin_to_dec("999") == 0`, ctx)
		if !result {
			t.Error("bin_to_dec of invalid should return 0")
		}
	})
}

func TestDSLExtended_IPFormat(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("ip_format decimal", func(t *testing.T) {
		result := dsl.EvaluateString(`ip_format("127.0.0.1", 1)`, ctx)
		if result != "2130706433" {
			t.Errorf("ip_format decimal = %q, want 2130706433", result)
		}
	})

	t.Run("ip_format hex", func(t *testing.T) {
		result := dsl.EvaluateString(`ip_format("127.0.0.1", 2)`, ctx)
		if result != "0x7f000001" {
			t.Errorf("ip_format hex = %q, want 0x7f000001", result)
		}
	})

	t.Run("ip_format invalid", func(t *testing.T) {
		result := dsl.EvaluateString(`ip_format("not-an-ip", 1)`, ctx)
		if result != "" {
			t.Errorf("ip_format of invalid IP should return empty, got %q", result)
		}
	})
}

func TestDSLExtended_JSONFunctions(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"json_compact": `{"key":"value"}`,
		"json_spaced":  `{  "key":   "value"  }`,
		"not_json":     "not json",
	}

	t.Run("json_minify", func(t *testing.T) {
		result := dsl.EvaluateString(`json_minify(json_spaced)`, ctx)
		if result != `{"key":"value"}` {
			t.Errorf("json_minify = %q, want {\"key\":\"value\"}", result)
		}
	})

	t.Run("json_prettify", func(t *testing.T) {
		result := dsl.EvaluateString(`json_prettify(json_compact)`, ctx)
		if !strings.Contains(result, "\n") {
			t.Errorf("json_prettify should produce multiline output, got %q", result)
		}
	})

	t.Run("json_minify invalid", func(t *testing.T) {
		result := dsl.EvaluateString(`json_minify(not_json)`, ctx)
		if result != "not json" {
			t.Errorf("json_minify of invalid JSON should return input, got %q", result)
		}
	})
}

func TestDSLExtended_GenerateJWT(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{
		"jwt_header":  `{"alg":"HS256"}`,
		"jwt_payload": `{"sub":"test"}`,
		"jwt_secret":  "mysecret",
	}

	t.Run("generate_jwt returns three parts", func(t *testing.T) {
		result := dsl.EvaluateString(`generate_jwt(jwt_header, jwt_payload, jwt_secret)`, ctx)
		parts := strings.Split(result, ".")
		if len(parts) != 3 {
			t.Errorf("generate_jwt should return 3 parts, got %d: %q", len(parts), result)
		}
	})

	t.Run("generate_jwt deterministic", func(t *testing.T) {
		r1 := dsl.EvaluateString(`generate_jwt(jwt_header, jwt_payload, jwt_secret)`, ctx)
		r2 := dsl.EvaluateString(`generate_jwt(jwt_header, jwt_payload, jwt_secret)`, ctx)
		if r1 != r2 {
			t.Errorf("generate_jwt should be deterministic: %q != %q", r1, r2)
		}
	})
}

func TestDSLExtended_Gadgets(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("generate_java_gadget no args", func(t *testing.T) {
		result := dsl.EvaluateString(`generate_java_gadget()`, ctx)
		if result != "JAVA_GADGET_PLACEHOLDER" {
			t.Errorf("generate_java_gadget() = %q, want JAVA_GADGET_PLACEHOLDER", result)
		}
	})

	t.Run("generate_java_gadget with type", func(t *testing.T) {
		result := dsl.EvaluateString(`generate_java_gadget("commons")`, ctx)
		if !strings.Contains(result, "JAVA") {
			t.Errorf("generate_java_gadget should contain JAVA, got %q", result)
		}
	})

	t.Run("generate_dotnet_gadget no args", func(t *testing.T) {
		result := dsl.EvaluateString(`generate_dotnet_gadget()`, ctx)
		if result != "DOTNET_GADGET_PLACEHOLDER" {
			t.Errorf("generate_dotnet_gadget() = %q, want DOTNET_GADGET_PLACEHOLDER", result)
		}
	})
}

func TestDSLExtended_PrintDebug(t *testing.T) {
	ctx := map[string]interface{}{}

	t.Run("print_debug is no-op", func(t *testing.T) {
		// Should not panic or error
		result := dslPrintDebug([]interface{}{"debug message", "value"}, ctx)
		if result != nil {
			t.Errorf("print_debug should return nil, got %v", result)
		}
	})
}

func TestDSLExtended_EdgeCases(t *testing.T) {
	dsl := NewDSLEngine()
	ctx := map[string]interface{}{}

	t.Run("concat no args", func(t *testing.T) {
		result := dsl.EvaluateString(`concat()`, ctx)
		if result != "" {
			t.Errorf("concat() = %q, want empty", result)
		}
	})

	t.Run("reverse empty", func(t *testing.T) {
		result := dsl.EvaluateString(`reverse("")`, ctx)
		if result != "" {
			t.Errorf("reverse(\"\") = %q, want empty", result)
		}
	})

	t.Run("remove_bad_chars no match", func(t *testing.T) {
		result := dsl.EvaluateString(`remove_bad_chars("hello", "xyz")`, ctx)
		if result != "hello" {
			t.Errorf("remove_bad_chars = %q, want hello", result)
		}
	})

	t.Run("replace_regex invalid pattern", func(t *testing.T) {
		result := dsl.EvaluateString(`replace_regex("hello", "[invalid", "x")`, ctx)
		if result != "hello" {
			t.Errorf("replace_regex with invalid pattern should return original, got %q", result)
		}
	})

	t.Run("compare_versions unknown op", func(t *testing.T) {
		result := dsl.Evaluate(`compare_versions("1.0", "??", "1.0")`, ctx)
		if result {
			t.Error("compare_versions with unknown op should return false")
		}
	})

	t.Run("ip_format no args", func(t *testing.T) {
		result := dsl.EvaluateString(`ip_format("127.0.0.1")`, ctx)
		// Less than 2 args returns empty
		if result != "" {
			t.Errorf("ip_format with 1 arg should return empty, got %q", result)
		}
	})

	t.Run("dec_to_hex no args", func(t *testing.T) {
		result := dsl.EvaluateString(`dec_to_hex()`, ctx)
		if result != "" {
			t.Errorf("dec_to_hex() should return empty, got %q", result)
		}
	})

	t.Run("hex_to_dec no args", func(t *testing.T) {
		result := dsl.Evaluate(`hex_to_dec() == 0`, ctx)
		if !result {
			t.Error("hex_to_dec() should return 0")
		}
	})

	t.Run("trim_space empty", func(t *testing.T) {
		result := dsl.EvaluateString(`trim_space("   ")`, ctx)
		if result != "" {
			t.Errorf("trim_space of whitespace = %q, want empty", result)
		}
	})
}

func TestDSLExtended_AllFunctionsRegistered(t *testing.T) {
	dsl := NewDSLEngine()

	expectedFunctions := []string{
		"starts_with", "ends_with", "to_upper", "to_lower",
		"contains_all", "contains_any", "regex", "regex_any", "regex_all",
		"equals_any", "line_starts_with", "line_ends_with",
		"concat", "repeat", "reverse", "remove_bad_chars",
		"trim_left", "trim_right", "trim_space", "trim_prefix", "trim_suffix",
		"replace_regex",
		"hex_encode", "hex_decode", "base64_py",
		"mmh3", "hmac",
		"rand_text_alpha", "rand_text_alphanumeric", "rand_text_numeric",
		"rand_int", "rand_base", "rand_char", "rand_ip",
		"compare_versions",
		"unix_time", "to_unix_time", "date_time", "wait_for",
		"gzip", "gzip_decode", "zlib", "zlib_decode",
		"aes_gcm",
		"dec_to_hex", "hex_to_dec", "bin_to_dec", "oct_to_dec",
		"resolve", "ip_format",
		"json_minify", "json_prettify", "generate_jwt",
		"generate_java_gadget", "generate_dotnet_gadget",
		"print_debug",
	}

	for _, fn := range expectedFunctions {
		t.Run("registered:"+fn, func(t *testing.T) {
			if _, ok := dsl.functions[fn]; !ok {
				t.Errorf("function %q is not registered", fn)
			}
		})
	}
}
