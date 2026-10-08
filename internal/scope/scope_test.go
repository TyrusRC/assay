package scope

import "testing"

func TestScope_NilAllowsAll(t *testing.T) {
	var s *Scope
	if !s.InScope("http://anything.example/x") {
		t.Error("nil scope must allow everything")
	}
}

func TestScope_HostAllowlist(t *testing.T) {
	s, err := New([]string{"example.com", "*.api.example.com"}, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"https://example.com/":           true,
		"https://example.com/a/b?c=1":    true,
		"https://sub.api.example.com/v1": true,
		"https://api.example.com/v1":     true, // wildcard matches the apex too
		"https://evil.com/":              false,
		"https://notexample.com/":        false,
	}
	for u, want := range cases {
		if got := s.InScope(u); got != want {
			t.Errorf("InScope(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestScope_EmptyHostsAllowsAnyHost(t *testing.T) {
	s, err := New(nil, nil, []string{`/admin`}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !s.InScope("https://whatever.test/public") {
		t.Error("empty host list must allow any host")
	}
	if s.InScope("https://whatever.test/admin/panel") {
		t.Error("exclude path must apply regardless of host")
	}
}

func TestScope_DefaultExcludes(t *testing.T) {
	s, err := New([]string{"example.com"}, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"https://example.com/logout",
		"https://example.com/user/sign-out",
		"https://example.com/account/delete",
		"https://example.com/delete_account",
	} {
		if s.InScope(u) {
			t.Errorf("default excludes must block %q", u)
		}
	}
	if !s.InScope("https://example.com/dashboard") {
		t.Error("a normal path must stay in scope")
	}
}

func TestScope_IncludeAllowlist(t *testing.T) {
	s, err := New([]string{"example.com"}, []string{`^/api/`}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !s.InScope("https://example.com/api/users") {
		t.Error("included path must be in scope")
	}
	if s.InScope("https://example.com/web/home") {
		t.Error("path outside the include list must be out of scope")
	}
}

func TestScope_ExcludeBeatsInclude(t *testing.T) {
	s, err := New([]string{"example.com"}, []string{`^/api/`}, []string{`/api/internal`}, false)
	if err != nil {
		t.Fatal(err)
	}
	if s.InScope("https://example.com/api/internal/secret") {
		t.Error("exclude must win over include")
	}
}

func TestScope_InvalidPattern(t *testing.T) {
	if _, err := New(nil, []string{"("}, nil, false); err == nil {
		t.Error("an invalid regex must return an error")
	}
}

func TestScope_MalformedURLFailsClosed(t *testing.T) {
	s, _ := New([]string{"example.com"}, nil, nil, false)
	if s.InScope("://nonsense") {
		t.Error("a URL that does not parse must be out of scope")
	}
}
