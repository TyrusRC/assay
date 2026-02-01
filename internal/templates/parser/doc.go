// Package parser provides YAML parsing for nuclei-compatible security templates.
//
// The parser reads template definitions from YAML files and produces
// structured template objects that can be executed by the executor package.
// It handles template validation, request deserialization, matcher and
// extractor configuration, and metadata extraction.
//
// Features:
//   - Single file and directory-based template loading
//   - Strict mode for rejecting templates with unknown fields
//   - Nuclei template format compatibility
//   - Matcher and extractor validation during parse
package parser
