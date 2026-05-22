// Package htparser parses a local HackTricks markdown source tree and
// extracts payloads into a Catalog the rest of the scanner can consume.
//
// HackTricks doesn't have PayloadAllTheThings' clean top-level
// attack-class folders, so classification is driven by path-keyword
// rules in classKeywords (sql-injection → sqli, xss-cross-site-scripting
// → xss, etc.). Pages whose path doesn't match any rule are skipped;
// emitting unclassified payloads would only feed noise into detectors.
//
// Build-artifact directories (node_modules, _book, site, .git) are
// pruned during the walk so vendored deps and mkdocs output never
// pollute the catalog.
//
// Markdown extraction reuses patparser.ExtractMarkdownBlocks for fence
// parsing and language-tag filtering; the only thing that's different
// here is how class is decided.
package htparser
