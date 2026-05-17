package stacktrace

import "regexp"

// frameworkPattern bundles a compiled regex with the framework it
// signals. Detection iterates these in declared order and reports the
// first match per probe.
type frameworkPattern struct {
	Framework string
	Pattern   *regexp.Regexp
}

// frameworkPatterns is the curated regex set. Each framework lists
// multiple expressions — any single match is enough. The patterns are
// intentionally narrow: they target syntactic shapes that almost never
// appear in non-error HTML/JSON bodies (e.g. `at com.foo.Bar(Bar.java:42)`,
// `Traceback (most recent call last)`, `goroutine 1 [running]`).
var frameworkPatterns = []frameworkPattern{
	// Java / Spring
	{Framework: "Java", Pattern: regexp.MustCompile(`at [a-zA-Z_.]+\([A-Za-z0-9_]+\.java:\d+\)`)},
	{Framework: "Java", Pattern: regexp.MustCompile(`org\.springframework`)},
	{Framework: "Java", Pattern: regexp.MustCompile(`java\.lang\.\w+Exception`)},

	// .NET
	{Framework: ".NET", Pattern: regexp.MustCompile(`System\.\w+Exception`)},
	{Framework: ".NET", Pattern: regexp.MustCompile(`at [A-Z][a-zA-Z.]+\(`)},
	{Framework: ".NET", Pattern: regexp.MustCompile(`\\bin\\Debug\\`)},

	// Python
	{Framework: "Python", Pattern: regexp.MustCompile(`Traceback \(most recent call last\)`)},
	{Framework: "Python", Pattern: regexp.MustCompile(`File "[^"]+", line \d+`)},
	{Framework: "Python", Pattern: regexp.MustCompile(`\w+Error: `)},

	// Ruby / Rails
	{Framework: "Ruby", Pattern: regexp.MustCompile("from /.+\\.rb:\\d+:in `")},
	{Framework: "Ruby", Pattern: regexp.MustCompile(`NoMethodError`)},
	{Framework: "Ruby", Pattern: regexp.MustCompile(`ActiveRecord::`)},

	// PHP
	{Framework: "PHP", Pattern: regexp.MustCompile(`Stack trace:\n#\d`)},
	{Framework: "PHP", Pattern: regexp.MustCompile(`Fatal error: `)},
	{Framework: "PHP", Pattern: regexp.MustCompile(`Notice: Undefined`)},
	{Framework: "PHP", Pattern: regexp.MustCompile(`Warning: `)},

	// Node.js
	{Framework: "Node.js", Pattern: regexp.MustCompile(`at \w+ \(/.+:\d+:\d+\)`)},
	{Framework: "Node.js", Pattern: regexp.MustCompile(`node_modules/`)},
	{Framework: "Node.js", Pattern: regexp.MustCompile(`at Module\._compile`)},

	// Go
	{Framework: "Go", Pattern: regexp.MustCompile(`goroutine \d+`)},
	{Framework: "Go", Pattern: regexp.MustCompile(`runtime error:`)},
	{Framework: "Go", Pattern: regexp.MustCompile(`panic: `)},
}
