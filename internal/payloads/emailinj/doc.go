// Package emailinj provides email header injection payloads for testing
// whether applications properly sanitize user input used in email headers.
//
// Payloads include CRLF injection sequences to add extra email headers
// (Cc, Bcc, Subject, To) and newline variations that bypass common filters.
//
// OWASP mappings:
//   - WSTG-INPV-10 (Testing for IMAP SMTP Injection)
//   - CWE-93 (Improper Neutralization of CRLF Sequences)
package emailinj
