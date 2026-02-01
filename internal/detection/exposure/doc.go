// Package exposure provides detection for sensitive file exposure vulnerabilities.
//
// The detector probes for inadvertently accessible files that may reveal
// sensitive information such as configuration files, backup archives,
// source code, credentials, and internal documentation.
//
// Detection techniques:
//   - Known sensitive path enumeration (e.g., .git, .env, web.config)
//   - Backup file detection (e.g., .bak, .old, .swp)
//   - Category-based filtering for targeted scans
//   - Response content analysis to confirm true positives
//
// OWASP mappings:
//   - WSTG-CONF-04 (Testing for Backup and Unreferenced Files)
//   - A05:2021 (Security Misconfiguration)
//   - CWE-538 (Insertion of Sensitive Information into Externally-Accessible File)
//   - CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)
package exposure
