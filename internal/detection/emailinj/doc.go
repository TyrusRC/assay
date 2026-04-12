// Package emailinj provides email header injection vulnerability detection.
//
// The detector identifies email header injection vulnerabilities by injecting
// CRLF sequences into email-related parameters and checking whether the
// application processes them as additional email headers (Cc, Bcc, To, Subject).
//
// Detection techniques:
//   - CRLF injection: inject newline sequences to add extra email headers
//   - Body injection: inject double newlines to add arbitrary email body content
//   - WAF bypass: use URL-encoded and alternative newline representations
//
// OWASP mappings:
//   - WSTG-INPV-10 (Testing for IMAP SMTP Injection)
//   - A03:2021 (Injection)
//   - CWE-93 (Improper Neutralization of CRLF Sequences)
package emailinj
