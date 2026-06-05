package compliance

// mappingFor returns the OWASP-category → controls table for a framework.
func mappingFor(fw Framework) map[string][]Control {
	switch fw {
	case PCIDSS:
		return pciMapping
	case HIPAA:
		return hipaaMapping
	case ISO27001:
		return isoMapping
	default:
		return nil
	}
}

// Mappings key the OWASP Top 10 (2025) categories to the framework controls
// most directly implicated. They are intentionally conservative and auditable:
// each entry reflects a control whose intent a finding in that category clearly
// undermines, not an exhaustive cross-reference.

var pciMapping = map[string][]Control{
	"A01": {{ID: "PCI 7.2", Title: "Restrict access to system components by business need-to-know"}},
	"A02": {{ID: "PCI 4.2", Title: "Strong cryptography during transmission of cardholder data"}, {ID: "PCI 3.5", Title: "Protect stored account data with strong cryptography"}},
	"A03": {{ID: "PCI 6.2.4", Title: "Address common software attacks (injection) in bespoke software"}},
	"A04": {{ID: "PCI 6.2.1", Title: "Develop software based on secure design principles"}},
	"A05": {{ID: "PCI 2.2", Title: "Configure system components securely (no insecure defaults)"}},
	"A06": {{ID: "PCI 6.3.3", Title: "Install applicable security patches for known vulnerabilities"}},
	"A07": {{ID: "PCI 8.3", Title: "Strong authentication for users and administrators"}},
	"A08": {{ID: "PCI 6.4.3", Title: "Manage and verify integrity of payment-page scripts"}},
	"A09": {{ID: "PCI 10.2", Title: "Implement audit logs for all system components"}},
	"A10": {{ID: "PCI 1.3", Title: "Restrict inbound/outbound traffic to that which is necessary"}},
}

var hipaaMapping = map[string][]Control{
	"A01": {{ID: "164.312(a)(1)", Title: "Access Control — unique access to ePHI by privilege"}},
	"A02": {{ID: "164.312(e)(1)", Title: "Transmission Security — encrypt ePHI in transit"}, {ID: "164.312(a)(2)(iv)", Title: "Encryption and Decryption of ePHI at rest"}},
	"A03": {{ID: "164.308(a)(1)", Title: "Security Management Process — reduce risks/vulnerabilities"}, {ID: "164.312(c)(1)", Title: "Integrity — protect ePHI from improper alteration"}},
	"A04": {{ID: "164.308(a)(1)(ii)(B)", Title: "Risk Management — implement security measures"}},
	"A05": {{ID: "164.308(a)(1)", Title: "Security Management Process — secure configuration"}},
	"A06": {{ID: "164.308(a)(1)(ii)(A)", Title: "Risk Analysis — assess vulnerabilities to ePHI"}},
	"A07": {{ID: "164.312(d)", Title: "Person or Entity Authentication"}},
	"A08": {{ID: "164.312(c)(1)", Title: "Integrity — guard against improper data alteration"}},
	"A09": {{ID: "164.312(b)", Title: "Audit Controls — record and examine activity"}},
	"A10": {{ID: "164.312(e)(1)", Title: "Transmission Security — control network access to ePHI"}},
}

var isoMapping = map[string][]Control{
	"A01": {{ID: "ISO A.5.15", Title: "Access control"}, {ID: "ISO A.8.3", Title: "Information access restriction"}},
	"A02": {{ID: "ISO A.8.24", Title: "Use of cryptography"}},
	"A03": {{ID: "ISO A.8.28", Title: "Secure coding"}},
	"A04": {{ID: "ISO A.8.27", Title: "Secure system architecture and engineering principles"}},
	"A05": {{ID: "ISO A.8.9", Title: "Configuration management"}},
	"A06": {{ID: "ISO A.8.8", Title: "Management of technical vulnerabilities"}},
	"A07": {{ID: "ISO A.8.5", Title: "Secure authentication"}},
	"A08": {{ID: "ISO A.8.28", Title: "Secure coding (data integrity)"}},
	"A09": {{ID: "ISO A.8.15", Title: "Logging"}},
	"A10": {{ID: "ISO A.8.22", Title: "Segregation of networks"}, {ID: "ISO A.8.20", Title: "Networks security"}},
}
