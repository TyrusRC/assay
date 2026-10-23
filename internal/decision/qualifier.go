package decision

import "strings"

// ImpactQualifier returns a context suffix for finding types where reflection
// alone does not prove exploitability. Appended to the evidence text sent to
// the ML engine so it can discriminate real exploits from noise.
func ImpactQualifier(findingType string) string {
	lower := strings.ToLower(findingType)
	switch {
	case strings.Contains(lower, "css injection"):
		return " No impact demonstrated — CSS reflection only."
	case strings.Contains(lower, "email") && strings.Contains(lower, "injection"):
		return " No SMTP interaction observed — header reflection only."
	case strings.Contains(lower, "ssi injection"):
		return " SSI directive reflected but server-side execution not confirmed."
	case strings.Contains(lower, "http parameter pollution"), strings.Contains(lower, "hpp"):
		return " Duplicate parameter accepted. No security impact demonstrated."
	case strings.Contains(lower, "html injection"):
		return " HTML content injected without script execution context."
	case strings.Contains(lower, "format string"):
		return " Format string reflected. No memory disclosure or crash confirmed."
	case strings.Contains(lower, "dom clobbering"):
		return " DOM element overwritten. No downstream security impact proven."
	case strings.Contains(lower, "reverse tabnabbing"):
		return " Link target overwritten. No credential theft or session hijack confirmed."
	case strings.Contains(lower, "content spoofing"):
		return " Content reflected without script execution or phishing context."
	case strings.Contains(lower, "text injection"):
		return " Text content injected. No code execution or markup interpretation confirmed."
	}
	return ""
}
