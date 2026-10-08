package deserialize

import "testing"

func TestSerializedShape(t *testing.T) {
	cases := []struct {
		name, value, want string
	}{
		{"data", "rO0ABXQABHRlc3Q=", "Java"},
		{"x", "aced0005737200", "Java"},
		{"__VIEWSTATE", "/wEPDwUKLT...", ".NET"},
		{"data", `O:8:"stdClass":0:{}`, "PHP"},
		{"data", "a:1:{i:0;s:3:\"abc\";}", "PHP"},
		{"m", "BAh7BjoGYUkiBmEGOgZFVA==", "Ruby"},
		{"p", "gASVBQAAAAAAAACMA2JhZA==", "Python"},
		{"id", "12345", ""},
		{"name", "hello world", ""},
	}
	for _, c := range cases {
		if got := serializedShape(c.name, c.value); got != c.want {
			t.Errorf("serializedShape(%q,%q) = %q, want %q", c.name, c.value, got, c.want)
		}
	}
}

func TestMatchDeserError(t *testing.T) {
	// Pattern present in body, absent from baseline -> that stack.
	if stack, _ := matchDeserError("... java.io.InvalidClassException: foo ...", "ok"); stack != "Java" {
		t.Errorf("Java deser error not matched, got %q", stack)
	}
	if stack, _ := matchDeserError("Warning: unserialize() error at offset 3", "ok"); stack != "PHP" {
		t.Errorf("PHP deser error not matched, got %q", stack)
	}
	// Pattern already in baseline -> not a delta -> no match.
	if stack, _ := matchDeserError("java.io.InvalidClassException", "java.io.InvalidClassException"); stack != "" {
		t.Errorf("baseline-present pattern should not match, got %q", stack)
	}
	// Clean response -> no match.
	if stack, _ := matchDeserError("all good", "all good"); stack != "" {
		t.Errorf("clean response matched, got %q", stack)
	}
}
