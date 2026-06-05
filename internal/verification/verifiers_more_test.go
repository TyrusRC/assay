package verification

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TyrusRC/assay/internal/core"
	httpx "github.com/TyrusRC/assay/internal/http"
)

func TestEngine_VerifySSTI_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("name")
		// Vulnerable: evaluates the template expression.
		if strings.Contains(q, "*") {
			parts := strings.SplitN(strings.Trim(q, "{}$#<%= /"), "*", 2)
			if len(parts) == 2 {
				a := atoiSafe(parts[0])
				b := atoiSafe(strings.TrimRight(parts[1], "}%> "))
				writeHTML(w, "Hello "+itoa(a*b))
				return
			}
		}
		writeHTML(w, "Hello "+q)
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("Server-Side Template Injection (SSTI)", srv.URL+"/?name=x", "name")
	proof, had := eng.Verify(context.Background(), f)
	if !had || proof == nil || !proof.Confirmed {
		t.Fatalf("expected confirmed SSTI, got had=%v proof=%+v", had, proof)
	}
	if f.Confidence != core.ConfidenceConfirmed {
		t.Errorf("expected confirmed confidence, got %s", f.Confidence)
	}
}

func TestEngine_VerifySSTI_ReflectionNotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflects the expression literally; does not evaluate it.
		writeHTML(w, "Hello "+r.URL.Query().Get("name"))
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("Server-Side Template Injection (SSTI)", srv.URL+"/?name=x", "name")
	proof, _ := eng.Verify(context.Background(), f)
	if proof != nil && proof.Confirmed {
		t.Fatalf("literal reflection must not confirm SSTI: %+v", proof)
	}
}

func TestEngine_VerifyLFI_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "etc/passwd") {
			writeHTML(w, "root:x:0:0:root:/root:/bin/bash\n")
			return
		}
		writeHTML(w, "not found")
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("Local File Inclusion / Path Traversal", srv.URL+"/?file=x", "file")
	proof, had := eng.Verify(context.Background(), f)
	if !had || proof == nil || !proof.Confirmed {
		t.Fatalf("expected confirmed LFI, got had=%v proof=%+v", had, proof)
	}
}

func TestEngine_VerifyLFI_NotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, "nothing sensitive here")
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("Local File Inclusion / Path Traversal", srv.URL+"/?file=x", "file")
	proof, _ := eng.Verify(context.Background(), f)
	if proof != nil && proof.Confirmed {
		t.Fatalf("no file marker must not confirm LFI: %+v", proof)
	}
}

func TestEngine_VerifyCRLF_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vulnerable app writes the param into a response header; a CRLF in the
		// value splits out an attacker-controlled header.
		v := r.URL.Query().Get("redir")
		for _, line := range strings.Split(v, "\n") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "\r"))
			if name, val, ok := strings.Cut(line, ": "); ok && strings.HasPrefix(name, "X-Assay") {
				w.Header().Set(name, val)
			}
		}
		writeHTML(w, "redirecting")
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("CRLF Injection", srv.URL+"/?redir=x", "redir")
	proof, had := eng.Verify(context.Background(), f)
	if !had || proof == nil || !proof.Confirmed {
		t.Fatalf("expected confirmed CRLF, got had=%v proof=%+v", had, proof)
	}
}

func TestEngine_VerifyCRLF_NotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeHTML(w, "ok")
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("CRLF Injection", srv.URL+"/?redir=x", "redir")
	proof, _ := eng.Verify(context.Background(), f)
	if proof != nil && proof.Confirmed {
		t.Fatalf("no header injection must not confirm CRLF: %+v", proof)
	}
}

func TestEngine_VerifySQLiBoolean_Confirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		// Vulnerable: a true condition returns rows, a false one returns none.
		if strings.Contains(q, "1=1") || strings.Contains(q, "'1'='1") {
			writeHTML(w, "<table><tr>alice</tr><tr>bob</tr><tr>carol</tr></table> many rows here padding padding")
			return
		}
		writeHTML(w, "<table></table>")
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("SQL Injection (boolean-blind)", srv.URL+"/?id=1", "id")
	proof, had := eng.Verify(context.Background(), f)
	if !had || proof == nil || !proof.Confirmed {
		t.Fatalf("expected confirmed boolean SQLi, got had=%v proof=%+v", had, proof)
	}
}

func TestEngine_VerifySQLiBoolean_NotConfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Same response regardless of the injected condition.
		writeHTML(w, "<table><tr>static</tr></table>")
	}))
	defer srv.Close()

	eng := NewEngine(httpx.NewClient())
	f := newFinding("SQL Injection", srv.URL+"/?id=1", "id")
	proof, _ := eng.Verify(context.Background(), f)
	if proof != nil && proof.Confirmed {
		t.Fatalf("identical true/false responses must not confirm SQLi: %+v", proof)
	}
}

// atoiSafe parses leading digits from s, ignoring non-digits.
func atoiSafe(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			continue
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
