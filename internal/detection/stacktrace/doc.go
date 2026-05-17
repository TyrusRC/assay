// Package stacktrace detects framework-specific stack traces leaked in
// HTTP responses. It targets the OWASP WSTG-ERRH-01 (Improper Error
// Handling) and WSTG-ERRH-02 (Stack Traces) test cases.
//
// The detector probes a target with a small set of malformed inputs
// (oversized query parameters, malformed JSON bodies, invalid
// Content-Type, path traversal markers, ?_=NaN noise) and diffs the
// resulting bodies against a clean baseline. A response that contains a
// recognised framework stack trace pattern which is NOT present in the
// baseline is flagged as a Medium-severity information-disclosure
// finding tied to A02:2025 (Security Misconfiguration), CWE-209 and
// CWE-200.
//
// Recognised frameworks:
//
//	Java / Spring  — at <pkg>.<class>(<File>.java:<line>), java.lang.*Exception
//	.NET           — System.<Foo>Exception, at Pascal.Cased.Method(, \bin\Debug\
//	Python         — Traceback (most recent call last), File "...", line N
//	Ruby / Rails   — from /...rb:NN:in `method`, NoMethodError, ActiveRecord::
//	PHP            — Stack trace:\n#N, Fatal error:, Notice: Undefined, Warning:
//	Node.js        — at Module._compile, node_modules/, "at foo (/path:N:N)"
//	Go             — goroutine N, runtime error:, panic:
package stacktrace
