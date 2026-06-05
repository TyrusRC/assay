package crawl

import "testing"

func TestFingerprint_StructuralAndStable(t *testing.T) {
	a := `<html><title>X</title><body><a href="/x">x</a><a href="/y">y</a>
		<form action="/login" method="post"><input name="user"><input name="pass"></form></body></html>`
	// Same structure, different visible text and link order → same fingerprint.
	b := `<html><title>Totally different title</title><body><a href="/y">why</a><a href="/x">ecks</a>
		<form method="POST" action="/login"><input name="pass"><input name="user"></form></body></html>`
	if Fingerprint(a) != Fingerprint(b) {
		t.Errorf("structurally identical pages should share a fingerprint:\n%s\n%s", Fingerprint(a), Fingerprint(b))
	}

	// A new link changes the state shape → different fingerprint.
	c := a + `<a href="/admin">admin</a>`
	if Fingerprint(a) == Fingerprint(c) {
		t.Error("adding a link should change the fingerprint")
	}
}

func TestExtractLinks(t *testing.T) {
	html := `<a href="/a">a</a><a href="b/c">bc</a><a href="https://other.test/z">z</a><a>noref</a>`
	links := extractLinks(html)
	if len(links) != 3 {
		t.Fatalf("expected 3 hrefs, got %d: %v", len(links), links)
	}
}

func TestExtractForms(t *testing.T) {
	html := `<form action="/login" method="post"><input name="u"><input name="p"></form>
		<form><input name="q"></form>`
	forms := extractForms(html)
	if len(forms) != 2 {
		t.Fatalf("expected 2 forms, got %d", len(forms))
	}
	if forms[0].Action != "/login" || forms[0].Method != "POST" {
		t.Errorf("unexpected form0: %+v", forms[0])
	}
	if forms[1].Method != "GET" {
		t.Errorf("form without method should default to GET, got %q", forms[1].Method)
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"https://h.test/a/b?x=1#f": "/a/b",
		"/a/b/":                    "/a/b",
		"/":                        "/",
		"relative/path":            "relative/path",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}
