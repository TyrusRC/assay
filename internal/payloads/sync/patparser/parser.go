package patparser

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Payload is one extracted item from PayloadAllTheThings — a value
// suitable for fuzzing or detector replay, plus enough provenance to
// trace it back to the source file.
type Payload struct {
	// Class is the canonical attack slug (sqli, xss, ssti, lfi, ...).
	Class string
	// Subtype is the file basename without extension, used to
	// disambiguate within a class (e.g. "MySQL Injection" vs
	// "PostgreSQL Injection").
	Subtype string
	// Value is the payload string.
	Value string
	// Source is the absolute path the payload was read from.
	Source string
	// Lang is the markdown code-block language tag, or "" for raw
	// .txt files / untagged fences.
	Lang string
}

// Catalog bundles all payloads parsed from a PayloadAllTheThings tree.
type Catalog struct {
	Payloads []Payload
	// Sources records the top-level class folders that were visited.
	Sources []string
}

// maxPayloadLen rejects entire script listings that happen to live in a
// code fence. PayloadAllTheThings payloads are virtually always under
// 512 bytes; raising the cap risks catching multi-line PoCs.
const maxPayloadLen = 512

// classByFolder maps PayloadAllTheThings top-level folder names to the
// canonical attack-class slug used by detectors. Unmapped folders fall
// back to a slugified form so new categories surface without code
// changes (TestParseDir_UnknownFolder).
var classByFolder = map[string]string{
	"SQL Injection":                    "sqli",
	"XSS Injection":                    "xss",
	"Server Side Template Injection":   "ssti",
	"Server Side Includes Injection":   "ssi",
	"Server Side Request Forgery":      "ssrf",
	"File Inclusion":                   "lfi",
	"Command Injection":                "cmdi",
	"NoSQL Injection":                  "nosql",
	"LDAP Injection":                   "ldap",
	"XPATH Injection":                  "xpath",
	"XXE Injection":                    "xxe",
	"JSON Web Token":                   "jwt",
	"Open Redirect":                    "redirect",
	"CSRF Injection":                   "csrf",
	"CRLF Injection":                   "crlf",
	"Insecure Deserialization":         "deser",
	"Prototype Pollution":              "protopollution",
	"Type Juggling":                    "typejuggling",
	"Web Cache Deception":              "cachedeception",
	"Web Sockets":                      "ws",
	"GraphQL Injection":                "graphql",
	"Headers Exploitation":             "hosthdr",
	"Insecure Direct Object Reference": "idor",
	"HTTP Parameter Pollution":         "hpp",
	"JNDI Injection":                   "jndi",
	"OAuth":                            "oauth",
	"SAML Injection":                   "samlinj",
	"Upload Insecure Files":            "fileupload",
	"Mass Assignment":                  "massassign",
	"ORM Leak":                         "ormleak",
	"DOM Clobbering":                   "domclobber",
	"CSV Injection":                    "csvinj",
	"Email Injection":                  "emailinj",
	"Regular Expression":               "redos",
	"Race Condition":                   "racecond",
	"Open Redirect Vulnerability":      "redirect",
	"CSS Injection":                    "cssinj",
	"HTML Injection":                   "htmlinj",
}

// nonPayloadLangs is the set of code-block language tags that almost
// never carry useful payloads (shell command examples, exploit
// scripts, expected-response listings). Filtering these out cuts the
// noise floor dramatically.
var nonPayloadLangs = map[string]bool{
	"bash":       true,
	"sh":         true,
	"shell":      true,
	"console":    true,
	"powershell": true,
	"ps1":        true,
	"diff":       true,
	"json":       true, // typically example responses, not payloads
	"text":       true,
	"plaintext":  true,
}

// ParseFile parses a single markdown or text file and returns the
// payloads it carries, tagged with class.
func ParseFile(path, class string) ([]Payload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("patparser: read %s: %w", path, err)
	}

	subtype := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".md", ".markdown":
		return extractCodeBlocks(string(data), class, subtype, path), nil
	case ".txt":
		return extractLines(string(data), class, subtype, path), nil
	}
	return nil, nil
}

// ParseDir walks rootDir treating its top-level subdirectories as
// PayloadAllTheThings attack-class folders. Each folder's markdown and
// .txt files are parsed and tagged with the folder's class slug.
func ParseDir(rootDir string) (*Catalog, error) {
	entries, err := os.ReadDir(rootDir)
	if err != nil {
		return nil, fmt.Errorf("patparser: readdir %s: %w", rootDir, err)
	}

	cat := &Catalog{
		Payloads: make([]Payload, 0, 256),
		Sources:  make([]string, 0, len(entries)),
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		folder := e.Name()
		class := classForFolder(folder)
		cat.Sources = append(cat.Sources, folder)

		walkErr := filepath.Walk(filepath.Join(rootDir, folder),
			func(p string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return err
				}
				if !isPayloadFile(p) {
					return nil
				}
				items, perr := ParseFile(p, class)
				if perr != nil {
					return perr
				}
				cat.Payloads = append(cat.Payloads, items...)
				return nil
			})
		if walkErr != nil {
			return cat, walkErr
		}
	}
	return cat, nil
}

// classForFolder returns the canonical class slug for a top-level
// PayloadAllTheThings folder name, falling back to a slugified form
// for folders not in our map.
func classForFolder(folder string) string {
	if c, ok := classByFolder[folder]; ok {
		return c
	}
	return slugify(folder)
}

// slugify lowercases s and replaces runs of non-alphanumeric characters
// with single hyphens. Used as the fallback class slug.
func slugify(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// isPayloadFile reports whether p has an extension we know how to
// parse. PayloadAllTheThings uses .md for guides and .txt for raw
// Intruder lists.
func isPayloadFile(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".md" || ext == ".markdown" || ext == ".txt"
}

// extractCodeBlocks scans a markdown document for fenced code blocks
// and emits each non-trivial line as a Payload. Bash / shell / json
// blocks are skipped (see nonPayloadLangs).
func extractCodeBlocks(body, class, subtype, source string) []Payload {
	out := make([]Payload, 0, 16)
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	inFence := false
	var fenceLang string
	for scanner.Scan() {
		line := scanner.Text()
		trim := strings.TrimSpace(line)

		if strings.HasPrefix(trim, "```") {
			if !inFence {
				inFence = true
				fenceLang = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(trim, "```")))
				continue
			}
			inFence = false
			fenceLang = ""
			continue
		}
		if !inFence {
			continue
		}
		if nonPayloadLangs[fenceLang] {
			continue
		}
		v := line
		if !isUsablePayload(v) {
			continue
		}
		out = append(out, Payload{
			Class:   class,
			Subtype: subtype,
			Value:   v,
			Source:  source,
			Lang:    fenceLang,
		})
	}
	return out
}

// extractLines reads a one-payload-per-line .txt file. Comment lines
// (# prefix) and blank lines are skipped.
func extractLines(body, class, subtype, source string) []Payload {
	out := make([]Payload, 0, 32)
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		v := scanner.Text()
		trim := strings.TrimSpace(v)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if !isUsablePayload(v) {
			continue
		}
		out = append(out, Payload{
			Class:   class,
			Subtype: subtype,
			Value:   v,
			Source:  source,
		})
	}
	return out
}

// isUsablePayload returns false for blank lines and oversize values
// that almost certainly aren't single payloads (full PoC listings).
func isUsablePayload(v string) bool {
	t := strings.TrimSpace(v)
	if t == "" {
		return false
	}
	if len(v) > maxPayloadLen {
		return false
	}
	return true
}
