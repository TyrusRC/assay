// Package auth provides payloads for authentication security testing.
package auth

// DefaultCredential represents a common default credential pair.
type DefaultCredential struct {
	Username    string
	Password    string
	Service     string
	Description string
}

var defaultCredentials = []DefaultCredential{
	// Common defaults
	{Username: "admin", Password: "admin", Service: "generic", Description: "Common admin default"},
	{Username: "admin", Password: "password", Service: "generic", Description: "Common admin password"},
	{Username: "admin", Password: "123456", Service: "generic", Description: "Common admin numeric"},
	{Username: "admin", Password: "admin123", Service: "generic", Description: "Common admin variant"},
	{Username: "administrator", Password: "administrator", Service: "generic", Description: "Administrator default"},
	{Username: "root", Password: "root", Service: "generic", Description: "Root default"},
	{Username: "root", Password: "toor", Service: "generic", Description: "Root reversed"},
	{Username: "test", Password: "test", Service: "generic", Description: "Test account"},
	{Username: "guest", Password: "guest", Service: "generic", Description: "Guest account"},
	{Username: "user", Password: "user", Service: "generic", Description: "User default"},
	{Username: "demo", Password: "demo", Service: "generic", Description: "Demo account"},

	// Web applications
	{Username: "admin", Password: "admin", Service: "wordpress", Description: "WordPress default"},
	{Username: "admin", Password: "password", Service: "joomla", Description: "Joomla default"},
	{Username: "admin", Password: "admin", Service: "drupal", Description: "Drupal default"},

	// Databases
	{Username: "root", Password: "", Service: "mysql", Description: "MySQL root no password"},
	{Username: "sa", Password: "", Service: "mssql", Description: "MSSQL sa no password"},
	{Username: "sa", Password: "sa", Service: "mssql", Description: "MSSQL sa default"},
	{Username: "postgres", Password: "postgres", Service: "postgresql", Description: "PostgreSQL default"},

	// Network devices
	{Username: "admin", Password: "admin", Service: "router", Description: "Router default"},
	{Username: "admin", Password: "", Service: "router", Description: "Router no password"},
	{Username: "cisco", Password: "cisco", Service: "cisco", Description: "Cisco default"},
}

// EnumerationPayload represents a payload for username enumeration testing.
type EnumerationPayload struct {
	ValidUser   string
	InvalidUser string
	Description string
}

var enumerationPayloads = []EnumerationPayload{
	{ValidUser: "admin", InvalidUser: "nonexistent_user_xyz_12345", Description: "Admin vs nonexistent user"},
	{ValidUser: "root", InvalidUser: "fake_user_abc_98765", Description: "Root vs nonexistent user"},
	{ValidUser: "test", InvalidUser: "invalid_test_user_00000", Description: "Test vs nonexistent user"},
}

// PasswordPolicyCheck represents a weak password to test policy enforcement.
type PasswordPolicyCheck struct {
	Password    string
	Weakness    string
	Description string
}

var policyChecks = []PasswordPolicyCheck{
	{Password: "a", Weakness: "too_short", Description: "Single character password"},
	{Password: "123", Weakness: "too_short", Description: "Three digit password"},
	{Password: "password", Weakness: "common", Description: "Common password"},
	{Password: "12345678", Weakness: "numeric_only", Description: "Numeric only password"},
	{Password: "aaaaaaaa", Weakness: "no_complexity", Description: "No complexity password"},
}

// GetDefaultCredentials returns all default credential pairs.
func GetDefaultCredentials() []DefaultCredential {
	return defaultCredentials
}

// GetByService returns credentials for a specific service.
func GetByService(service string) []DefaultCredential {
	var result []DefaultCredential
	for _, c := range defaultCredentials {
		if c.Service == service {
			result = append(result, c)
		}
	}
	return result
}

// GetEnumerationPayloads returns username enumeration test payloads.
func GetEnumerationPayloads() []EnumerationPayload {
	return enumerationPayloads
}

// GetPasswordPolicyChecks returns weak passwords for policy testing.
func GetPasswordPolicyChecks() []PasswordPolicyCheck {
	return policyChecks
}
