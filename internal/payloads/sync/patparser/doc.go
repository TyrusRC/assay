// Package patparser parses a local PayloadAllTheThings clone and
// extracts payloads into a typed Catalog the rest of the scanner can
// consume.
//
// Two file shapes are recognised:
//   - .md / .markdown — fenced code blocks (```lang ... ```) become
//     Payload entries, tagged with the block's language. Bash / shell /
//     JSON fences are skipped because they typically carry exploit
//     command examples or example responses, not payloads.
//   - .txt — Intruder/ raw lists, one payload per line, # comments
//     and blank lines stripped.
//
// Top-level folders in the cloned repo map to canonical attack-class
// slugs via classByFolder; unknown folders fall back to a slugified
// folder name so new categories surface without code changes.
//
// The parser is offline: it reads from a path the caller already
// cloned. Network fetching of the upstream repo lives elsewhere.
package patparser
