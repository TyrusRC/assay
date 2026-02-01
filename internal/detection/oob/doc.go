// Package oob provides Out-of-Band (OOB) testing capabilities using interactsh.
//
// OOB testing is essential for detecting blind vulnerabilities that don't
// produce visible responses, such as:
//   - Blind SQL Injection (via DNS/HTTP callbacks)
//   - Blind XXE (XML External Entity)
//   - Blind SSRF (Server-Side Request Forgery)
//   - Blind RCE (Remote Code Execution)
//   - Blind SSTI (Server-Side Template Injection)
package oob
