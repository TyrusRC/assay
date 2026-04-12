// Package ssi provides Server-Side Include injection vulnerability detection.
//
// The detector identifies SSI injection vulnerabilities by sending SSI
// directives (exec, include, echo) through user-controllable parameters and
// checking whether the server processes them, indicating the application
// fails to sanitize SSI syntax from user input.
//
// Detection techniques:
//   - Command execution: inject exec directives and check for command output
//   - File inclusion: inject include directives and check for file contents
//   - Variable echo: inject echo directives and check for server variable values
//
// OWASP mappings:
//   - WSTG-INPV-08 (Testing for SSI Injection)
//   - A03:2021 (Injection)
//   - CWE-97 (Improper Neutralization of Server-Side Includes)
package ssi
