// Package massassign provides mass assignment vulnerability detection.
//
// The detector identifies mass assignment vulnerabilities by sending extra JSON
// fields in PUT/POST requests and checking if the server accepts and reflects
// them in responses, indicating unprotected binding of request data to internal
// objects.
//
// Tested fields:
//   - Privilege escalation: isAdmin, role, admin, permissions
//   - Identity manipulation: id, user_id, email, username
//   - Status changes: verified, active, approved, account_type
//
// Detection techniques:
//   - JSON field reflection analysis
//   - Response differential comparison
//   - Status code change detection
//
// OWASP mappings:
//   - WSTG-INPV-20 (Testing for Mass Assignment)
//   - A01:2023-API (Broken Object Level Authorization)
//   - CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
package massassign
