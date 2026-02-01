// Package payloads provides curated vulnerability testing payloads.
//
// Payloads are sourced from well-known security resources:
//   - PayloadsAllTheThings (https://github.com/swisskyrepo/PayloadsAllTheThings)
//   - HackTricks (https://book.hacktricks.xyz/)
//   - HackVectors (https://github.com/nicholasaleks/HackVectors)
//
// Each payload category provides:
//   - Context-aware payloads for different injection points
//   - Evasion variants for WAF bypass
//   - Platform-specific payloads where applicable
//
// Usage:
//
//	// Get SQL injection payloads for MySQL
//	payloads := sqli.GetPayloads(sqli.MySQL)
//
//	// Get XSS payloads for HTML context
//	payloads := xss.GetPayloads(xss.HTMLContext)
package payloads
