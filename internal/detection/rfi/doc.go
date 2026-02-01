// Package rfi provides detection for Remote File Inclusion vulnerabilities.
//
// RFI occurs when an application includes a remote file via user-controlled
// input, allowing attackers to execute arbitrary code hosted on external
// servers or access internal resources through URL-based file inclusion.
//
// Detection techniques:
//   - Remote URL inclusion testing with known canary files
//   - Protocol wrapper exploitation (http://, ftp://, data://)
//   - Response content analysis for inclusion confirmation
//   - WAF bypass techniques for filtered inputs
//
// OWASP mappings:
//   - WSTG-INPV-11 (Testing for Code Injection)
//   - A03:2021 (Injection)
//   - CWE-98 (Improper Control of Filename for Include/Require Statement)
package rfi
